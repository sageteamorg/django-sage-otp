import base64
import logging
import secrets

from django.contrib.auth import get_user_model
from sage_tools.repository.generator import BaseDataGenerator

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.models import OTP
from sage_otp.utils import generate_totp

# pylint: disable=C0103
User = get_user_model()
logger = logging.getLogger(__name__)


class DataGeneratorLayer(BaseDataGenerator):
    """
    A class responsible for generating fake data for user table.

    Inherits from BaseDataGenerator for data generation utilities.
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize the WarehouseDataGenerator.

        Attributes:
            priority_counter (itertools.count): A counter that generates
            sequential priority values for generated data.
        """
        super().__init__(*args, **kwargs)

    def _generate_otp_for_user(self, user, reason, state):
        urlsafe_token = secrets.token_urlsafe(16)
        base32_secret = base64.b32encode(urlsafe_token.encode("utf-8")).decode("utf-8")
        token = generate_totp(base32_secret.upper())
        return OTP(
            user=user,
            token=token,
            state=state,
            reason=reason,
        )

    def generate_otp_for_users(self):
        """Generates OTPs for all users in the system."""
        users = User.objects.all()
        otps = []

        for user in users:
            reasons = list({secrets.choice(ReasonOptions.values) for _ in range(3)})
            for reason in reasons:
                otp = self._generate_otp_for_user(
                    user, reason, secrets.choice(OTPState.values)
                )
                otps.append(otp)

        onetime_passwords = OTP.objects.bulk_create(otps)

        return onetime_passwords
