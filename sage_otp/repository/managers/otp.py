"""
This module provides a Django manager class
for handling OTP (One-Time Password) operations,.

including generation, validation, and management of OTPs for user authentication.
"""

import base64
import logging
import secrets
from datetime import timedelta
from django.conf import settings
from typing import Dict, NoReturn, Optional, TypeVar, Union

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Manager, Q
from django.utils import timezone

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import UserLockedException
from sage_otp.signals.otp import (
    otp_created,
    otp_expired,
    otp_failed,
    otp_locked,
    otp_reset,
    otp_secret_generated,
    otp_sent,
    otp_validated
)
from sage_otp.helpers.exceptions import (
    OTPDoesNotExists,
    OTPException,
    OTPExpiredException,
)
from sage_otp.utils import generate_totp

logger = logging.getLogger(__name__)
User = get_user_model()
_T = TypeVar("_T", bound=models.Model)
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 120)


class OTPManager:
    """Handles OTP generation, validation, expiration, and session lifecycle."""

    EXPIRE_TIME = timedelta(seconds=getattr(settings, "OTP_EXPIRE_TIME", 300))
    LOCK_TIME = timedelta(seconds=getattr(settings, "OTP_LOCK_TIME", 3600))
    MAXIMUM_RESENDS = getattr(settings, "OTP_MAXIMUM_RESENDS", 5)
    MAXIMUM_WRONG_SUBMITS = getattr(settings, "OTP_MAXIMUM_WRONG_SUBMITS", 10)
    RESEND_TIME = timedelta(seconds=getattr(settings, "OTP_RESEND_TIME", 120))
    urlsafe_token = secrets.token_urlsafe(16)

    def resolve_user_by_identifier(self, identifier: Union[str, int]) -> User:
        identifier = str(identifier)
        try:
            if identifier.isdigit():
                return User.objects.get(pk=int(identifier))
            if "@" in identifier:
                return User.objects.get(email=identifier)
            if identifier.startswith("+"):
                return User.objects.get(phone_number=identifier)
        except User.DoesNotExist:
            logger.warning("OTP: User not found for identifier='%s'", identifier)
            raise OTPDoesNotExists(params={"identifier": identifier})

    def get_user_base32_secret(self, user: User) -> str:
        if not user.otp_secret:
            user.otp_secret = base64.b32encode(secrets.token_urlsafe(16).encode()).decode()
            user.save(update_fields=["otp_secret"])
            logger.info("New OTP secret generated for user_id=%s", user.id)
            otp_secret_generated.send(sender=self.__class__, user=user, secret=user.otp_secret)
        return user.otp_secret

    def get_otp(self, identifier: str, reason: str) -> _T:
        from sage_otp.models import OTP
        user = self.resolve_user_by_identifier(identifier)
        try:
            return OTP.objects.get(user=user, reason=reason, state=OTPState.ACTIVE)
        except OTP.DoesNotExist:
            logger.warning("OTP: No active OTP found for user_id=%s, reason='%s'", user.id, reason)
            raise OTPDoesNotExists(params={"identifier": identifier, "reason": reason})
        except OTP.MultipleObjectsReturned as e:
            logger.error("OTP: Multiple active OTPs found for identifier='%s', reason='%s'", identifier, reason)
            raise OTPException(str(e), params={"identifier": identifier, "reason": reason})

    def get_or_create_otp(self, identifier: str, reason: str) -> tuple[_T, bool]:
        from sage_otp.models import OTP
        user = self.resolve_user_by_identifier(identifier)
        active_otps = OTP.objects.filter(user=user, reason=reason, state=OTPState.ACTIVE)

        for otp in active_otps:
            if otp.created_at + timedelta(seconds=OTP_LIFETIME) <= timezone.now():
                otp.state = OTPState.EXPIRED
                otp.save(update_fields=["state"])
                otp_expired.send(sender=self.__class__, user=user, otp=otp)
                logger.info("OTP expired. OTP ID=%s, user_id=%s", otp.id, user.id)
            else:
                logger.debug("Using existing OTP. OTP ID=%s, user_id=%s", otp.id, user.id)
                return otp, False

        secret = self.get_user_base32_secret(user)
        otp = OTP.objects.create(
            user=user,
            reason=reason,
            token=generate_totp(secret),
            state=OTPState.ACTIVE,
            last_sent_at=timezone.now(),
        )
        otp_created.send(sender=self.__class__, user=user, otp=otp, reason=reason)
        logger.info("OTP created. OTP ID=%s, user_id=%s", otp.id, user.id)
        return otp, True

    def reset_otp(self, otp: _T) -> _T:
        otp.token = generate_totp(self.get_user_base32_secret(otp.user))
        otp.failed_attempts_count = 0
        otp.resend_requests_count = 0
        otp.lockout_end_time = None
        otp.state = OTPState.ACTIVE
        otp.save()
        logger.info("OTP reset. OTP ID=%s, user_id=%s", otp.id, otp.user.id)
        otp_reset.send(sender=self.__class__, user=otp.user, otp=otp)
        return otp

    def check_otp_last_sent_at(self, otp: _T) -> Optional[Dict[str, bool]]:
        if otp.last_sent_at and (otp.last_sent_at + self.RESEND_TIME > timezone.now()):
            remaining = int((otp.last_sent_at + self.RESEND_TIME - timezone.now()).seconds)
            logger.debug("OTP resend blocked. OTP ID=%s, remaining=%ss", otp.id, remaining)
            return {"resend_delay": True, "resend_release_time_remaining": remaining}
        return None

    def send_otp(self, identifier: str, reason: str) -> Optional[Dict[str, Union[bool, int]]]:
        otp, created = self.get_or_create_otp(identifier, reason)
        resend_data = self.check_otp_last_sent_at(otp)
        if resend_data:
            logger.info("OTP resend delayed. OTP ID=%s, user_id=%s", otp.id, otp.user.id)
            return resend_data

        otp.state = OTPState.ACTIVE
        otp.resend_requests_count += 1
        otp.last_sent_at = timezone.now()
        otp.save(update_fields=["state", "resend_requests_count", "last_sent_at"])

        logger.info("OTP sent. OTP ID=%s, user_id=%s", otp.id, otp.user.id)
        otp_sent.send(sender=self.__class__, user=otp.user, otp=otp, reason=reason)
        return None

    def check_otp(self, identifier: str, token: str, reason: str) -> Union[Dict[str, bool], NoReturn]:
        otp = self.get_otp(identifier, reason)

        if otp.is_expired():
            otp.state = OTPState.EXPIRED
            otp.save(update_fields=["state"])
            logger.warning("OTP expired during check. OTP ID=%s", otp.id)
            otp_expired.send(sender=self.__class__, user=otp.user, otp=otp)
            raise OTPExpiredException("Token has expired.")

        if otp.token == token and otp.state == OTPState.ACTIVE:
            otp.state = OTPState.CONSUMED
            otp.save(update_fields=["state"])
            logger.info("OTP verified. OTP ID=%s", otp.id)
            otp_validated.send(sender=self.__class__, user=otp.user, otp=otp)
            return {"token_is_correct": True}

        otp.failed_attempts_count += 1
        update_fields = ["failed_attempts_count"]
        log_level = logger.warning if otp.failed_attempts_count == 1 else logger.debug

        if otp.failed_attempts_count >= self.MAXIMUM_WRONG_SUBMITS:
            otp.lockout_end_time = timezone.now() + self.LOCK_TIME
            otp.state = OTPState.LOCKED
            update_fields += ["state", "lockout_end_time"]
            logger.warning("OTP locked. OTP ID=%s", otp.id)
            otp_locked.send(sender=self.__class__, user=otp.user, otp=otp)
            otp.save(update_fields=update_fields)
            raise UserLockedException("The user is locked due to too many failed attempts.")

        otp.save(update_fields=update_fields)
        log_level("OTP validation failed. OTP ID=%s, failed_attempts=%d", otp.id, otp.failed_attempts_count)
        otp_failed.send(sender=self.__class__, user=otp.user, otp=otp, failed_attempts_count=otp.failed_attempts_count)

        return {"token_is_correct": False}


class OtpBusinessLogicLayer(Manager, OTPManager):
    """
    Manager class for handling OTP (One-Time Password)
    operations with specific scenarios.

    This class extends the OTPService class and provides
    methods for sending OTPs for various scenarios,
    such as email activation, login, password reset, and phone number activation.
    """

    def send_email_activation_otp(self, email) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send OTP for email activation.

        Args:
            email (str): The email address of the user.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
                The lock status and remaining time, if locked.
        """
        return self.send_otp(email, reason=ReasonOptions.EMAIL_ACTIVATION)

    def send_login_otp(self, identifier) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send OTP for login.

        Args:
            identifier (str): The phone number or email of the user.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
                The lock status and remaining time, if locked.
        """
        return self.send_otp(identifier, reason=ReasonOptions.LOGIN)

    def send_reset_password_otp(
        self, identifier
    ) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send OTP for password reset.

        Args:
            identifier (str): The phone number or email of the user.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
                The lock status and remaining time, if locked.
        """
        return self.send_otp(identifier, reason=ReasonOptions.RESET_PASSWORD)

    def send_forget_password_otp(
        self, identifier
    ) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send OTP for forgotten password.

        Args:
            identifier (str): The phone number or email of the user.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
                The lock status and remaining time, if locked.
        """
        return self.send_otp(identifier, reason=ReasonOptions.FORGET_PASSWORD)

    def send_phone_number_activation_otp(
        self, phone_number: str
    ) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send OTP for phone number activation.

        Args:
            phone_number (str): The phone number of the user.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
                The lock status and remaining time, if locked.
        """
        return self.send_otp(phone_number, reason=ReasonOptions.PHONE_NUMBER_ACTIVATION)

    def verify_otp(
        self, identifier: str, token: str, reason: str
    ) -> Union[Dict[str, bool], NoReturn]:
        """
        Check the validity of the OTP provided by the user.

        Args:
            identifier (str): The phone number or email of the user.
            token (str): The OTP token provided by the user.
            reason (str): The reason for OTP generation (e.g., Registration).

        Returns:
            Union[Dict[str, bool], NoReturn]:
                - If the OTP is correct and not expired,
                    a dictionary with 'token_is_correct' set to True is returned.
                - If the OTP is incorrect,
                    a dictionary with 'token_is_correct' set to False is returned.
                - If the OTP has expired, an OTPExpiredException is raised.
        """
        return self.check_otp(
            identifier,
            token,
            reason,
        )
