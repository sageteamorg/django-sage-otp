"""
This module provides a Django manager class
for handling OTP (One-Time Password) operations,.

including generation, validation, and management of OTPs for user authentication.
"""

import base64
import logging
import secrets
from datetime import timedelta
from typing import Dict, NoReturn, Optional, TypeVar, Union

from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Manager, Q
from django.utils import timezone

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import (
    OTPDoesNotExists,
    OTPException,
    OTPExpiredException,
)
from sage_otp.utils import generate_totp

logger = logging.getLogger(__name__)

_T = TypeVar("_T", bound=models.Model)


class OTPManager:
    """
    Class for handling OTP operations.

    This class provides methods for generating, managing,
    and validating OTPs for user authentication.
    """

    EXPIRE_TIME = timedelta(seconds=300)
    LOCK_TIME = timedelta(hours=1)
    MAXIMUM_RESENDS = 5
    MAXIMUM_WRONG_SUBMITS = 10
    RESEND_TIME = timedelta(minutes=2)
    urlsafe_token = secrets.token_urlsafe(16)
    base32_secret = base64.b32encode(urlsafe_token.encode("utf-8")).decode("utf-8")

    def get_otp(self, identifier: str, reason: str) -> _T:
        """Create OTP for the user."""
        from sage_otp.models import OTP

        # pylint: disable=C0103
        User = get_user_model()

        user = User.objects.get(id=identifier)

        otp_query = (
            Q(user=user)
            & Q(reason=reason)
            & Q(state__in=[OTPState.ACTIVE])
        )

        try:
            otp = OTP.objects.get(otp_query)
        except OTP.DoesNotExist as e:
            raise OTPDoesNotExists(
                params={"identifier": identifier, "reason": reason}
            ) from e
        except OTP.MultipleObjectsReturned as e:
            raise OTPException(
                message=str(e), params={"identifier": identifier, "reason": reason}
            ) from e
        return otp

    def get_or_create_otp(self, identifier: str, reason: str) -> tuple[_T, bool]:
        """
        Retrieves an existing OTP or creates a new one for the user based on
        the specified reason.

        It looks for active or locked OTPs. If none are found, a new active OTP
        is created.

        Args:
            identifier (str): The identifier (phone number, email, or username)
            of the user.
            reason (str): The reason for OTP generation
            (e.g., 'Registration', 'Password Reset').

        Returns:
            OTP: The OTP instance, either fetched or newly created.
            created (bool): True if the OTP was created,
            False if it was retrieved.
        """
        from sage_otp.models import OTP

        User = get_user_model()
        user = User.objects.get(id=identifier)
        
        otp_query = {
            "user": user,
            "reason": reason,
            "state": OTPState.ACTIVE,
            "last_sent_at":timezone.now()
        }
        otp, created = OTP.objects.get_or_create(
            **otp_query,
            defaults={
                "token": generate_totp(self.base32_secret.upper()),
                "state": OTPState.ACTIVE,
            }
        )

        return otp, created

    def reset_otp(self, otp):
        """Reset the OTP to its initial state."""

        otp.token = generate_totp(self.base32_secret.upper())
        otp.failed_attempts_count = 0
        otp.resend_requests_count = 0
        otp.lockout_end_time = None
        otp.state = OTPState.ACTIVE
        return otp

    def check_otp_last_sent_at(self, otp) -> Optional[Dict[str, bool]]:
        """
        Check if user can request to resend otp and returns the status if not.

        Args:
            otp: The OTP instance.

        Returns:
            Optional[Dict[str, bool]]: The lock status
                and remaining time, if there is a resend delay.
        """
        if otp.last_sent_at:
            if (otp.last_sent_at + self.RESEND_TIME) > timezone.now():
                return {
                    "resend_delay": True,
                    "resend_release_time_remaining": int(
                        ((otp.last_sent_at + self.RESEND_TIME) - timezone.now()).seconds
                    ),
                }
        return None

    def send_otp(
        self, identifier: str, reason: str
    ) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Generate and send an OTP to the user's phone number or email address.

        It performs various checks, such as lock status and expiration,
        before sending the OTP.

        Args:
            identifier (str): The phone number or email of the user.
            reason (str): The reason for OTP generation.

        Returns:
            Optional[Dict[str, Union[bool, int]]]:
            None if the OTP is sent successfully,or lock status if locked.
        """
        # Unpack the tuple to get the OTP object and the 'created' boolean
        otp, created = self.get_or_create_otp(identifier, reason)

        # Check if OTP was recently sent and if the resend delay has passed
        resend_data = self.check_otp_last_sent_at(otp)
        if resend_data:
            return resend_data

        otp.state = OTPState.ACTIVE
        otp.resend_requests_count += 1
        otp.last_sent_at = timezone.now()
        otp.save()

        return None

    def check_otp(
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

        otp = self.get_otp(identifier, reason)
        # data = self.check_otp_lockout_end_time(otp)
        # if data:
        #     return data
        # otp = self.check_token_expiry(otp)
        # otp = self.check_lock_otp(otp)

        if otp.token == token and otp.state == OTPState.ACTIVE:
            otp.state = OTPState.CONSUMED
            logger.info("user:%s put the code successfully", identifier)
            otp.save()
            return {"token_is_correct": True}

        if otp.token == token and otp.state == OTPState.EXPIRED:
            logger.info("token:%s has been expired for user: %s", otp.token, identifier)
            raise OTPExpiredException("Token has been expired.")

        otp.failed_attempts_count += 1
        if otp.failed_attempts_count >= self.MAXIMUM_WRONG_SUBMITS:
            otp.lockout_end_time = timezone.now() + self.LOCK_TIME
            otp.state = OTPState.LOCKED
        otp.save()
        logger.info("user:%s did not put the code successfully", identifier)
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
