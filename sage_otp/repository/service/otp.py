import logging
from typing import TypeVar

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import models, transaction
from django.db.models import Q

from sage_otp.helpers import exceptions as exc
from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.utils import generate_totp

logger = logging.getLogger(__name__)

_T = TypeVar("_T", bound=models.Model)

User = get_user_model()

OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 120)


class OTPService:
    def get_otp(self, user, reason: str) -> _T:
        """
        Retrieves an active OTP for a given user and reason.

        This method ensures that only one active
        OTP exists for the specified criteria. If no active OTP is found,
        an OTPDoesNotExists exception is raised.
        If multiple active OTPs are found, an OTPException is raised.
        """
        from sage_otp.models import OTP

        otp_query = Q(user=user) & Q(reason=reason) & Q(state=OTPState.ACTIVE)

        try:
            otp = OTP.objects.get(otp_query)
        except OTP.DoesNotExist as error:
            raise exc.OTPDoesNotExists() from error

        except OTP.MultipleObjectsReturned as error:
            raise exc.OTPException() from error

        return otp

    def get_or_create_otp(
        self,
        user,
        reason: ReasonOptions,
        digits: int = 4,
        lifetime=OTP_LIFETIME,
        check_expiration: bool = True,
    ) -> tuple[_T, bool]:
        """
        Manages the OTP lifecycle for a user based on a specific reason,
        ensuring that only one active OTP exists per reason.

        This method checks for existing OTPs that have not expired and
        returns them; otherwise,
        it generates a new OTP. Expired OTPs are invalidated before generating
        a new OTP if `check_expiration` is enabled.

        Workflow:
        1. Starts a transaction to ensure atomicity.
        2. Invalidates expired OTPs if `check_expiration` is True.
        3. Generates a new OTP using the user's secret_key and
        provided parameters if no active OTP exists.
        4. Retrieves or creates an OTP entry in the database.
        5. Returns the OTP object and a flag indicating whether
        it was newly created.

        Example usage:
        >>> user = User.objects.get(username='example_user')
        >>> otp, created = get_or_create_otp(user, ReasonOptions.LOGIN)
        >>> if created:
        ...     print(f"New OTP generated: {otp.token}")
        ... else:
        ...     print(f"Existing active OTP: {otp.token}")
        """
        from sage_otp.models import OTP, OTPState

        with transaction.atomic():
            if check_expiration:
                self.expire_old_otp(user, reason)

            token = generate_totp(
                secret=user.secret_key, digits=digits, lifetime=lifetime
            )

            otp, created = OTP.objects.get_or_create(
                user=user,
                reason=reason,
                state=OTPState.ACTIVE,
                defaults={"token": token},
            )

            return otp, created

    def verify(self, user, reason: ReasonOptions, token: str) -> None:
        """
        Validates a given token for a specific user and reason.

        If the token is valid, the corresponding  OTP's state is set to
        CONSUMED.
        If the token is invalid, an exception is raised. The method handles
        OTP lookup and state management, encapsulating the verification
        logic within the OTP model.

        :param user: User instance for whom the token is to be verified.
        :param reason: Enum indicating the reason for the token verification.
        :param token: The token string to be verified.
        :raises InvalidTokenException: If the token is invalid or
        if no unique active OTP is found.
        """
        from sage_otp.models import OTP

        try:
            otp = self.get_otp(user, reason)
            is_validated, state = otp.is_valid_token(token)

            if is_validated:
                otp.state = OTPState.CONSUMED
                otp.save(update_fields=["state"])
            else:
                raise exc.InvalidTokenException()
        except (OTP.DoesNotExist, OTP.MultipleObjectsReturned) as e:
            raise exc.InvalidTokenException() from e

    def expire_old_otp(self, user, reason: ReasonOptions) -> None:
        """
        Expires any old OTPs for a given user and reason.

        This method looks up active OTPs and checks
        their expiration status. If an OTP is found to be expired,
        it is marked as EXPIRED in the database.

        :param user: User instance for whom old OTPs are to be expired.
        :param reason: Enum indicating the reason for expiring old OTPs.
        """
        from sage_otp.models import OTP, OTPState

        active_otp = OTP.objects.filter(
            user=user, reason=reason, state=OTPState.ACTIVE
        ).first()
        if active_otp and active_otp.is_expired():
            active_otp.state = OTPState.EXPIRED
            active_otp.save(update_fields=["state"])
