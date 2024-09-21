from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from sage_otp.helpers import exceptions as exc
from sage_otp.helpers.choices import ReasonOptions
from sage_otp.models import OTP, OTPState
from sage_otp.repository.service import OTPService

User = get_user_model()


@pytest.mark.django_db
class TestOTPService:
    """Test cases for the OTPService class."""

    @pytest.fixture
    def create_user(self):
        """Fixture to create a test user."""
        user = User.objects.create_user(username="testuser", password="password")
        user.secret_key = "secret"  # Dynamically add secret_key
        return user

    @pytest.fixture
    def create_otp(self, create_user):
        """Fixture to create an active OTP instance."""
        return OTP.objects.create(
            user=create_user,
            token="123456",
            state=OTPState.ACTIVE,
            reason=ReasonOptions.LOGIN,
            created_at=timezone.now(),
        )

    @pytest.fixture
    def expired_otp(self, create_user):
        """Fixture to create an expired OTP instance."""
        return OTP.objects.create(
            user=create_user,
            token="654321",
            state=OTPState.EXPIRED,
            reason=ReasonOptions.LOGIN,
            created_at=timezone.now() - timedelta(seconds=130),
        )

    def test_get_otp(self, create_user, create_otp):
        """Test that the correct OTP is retrieved based on user and reason."""
        otp_service = OTPService()
        otp = otp_service.get_otp(create_user, ReasonOptions.LOGIN)
        assert otp.token == "123456"
        assert otp.state == OTPState.ACTIVE

    def test_get_otp_does_not_exist(self, create_user):
        """Test that OTPDoesNotExists is raised if no active OTP is found."""
        otp_service = OTPService()
        with pytest.raises(exc.OTPDoesNotExists):
            otp_service.get_otp(create_user, ReasonOptions.LOGIN)

    def test_verify_valid_token(self, create_otp):
        """Test that a valid OTP token is correctly verified."""
        otp_service = OTPService()
        otp_service.verify(create_otp.user, ReasonOptions.LOGIN, "123456")
        create_otp.refresh_from_db()
        assert create_otp.state == OTPState.CONSUMED

    def test_verify_invalid_token(self, create_otp):
        """Test that an invalid OTP token raises InvalidTokenException."""
        otp_service = OTPService()
        with pytest.raises(exc.InvalidTokenException):
            otp_service.verify(create_otp.user, ReasonOptions.LOGIN, "wrong_token")

    def test_expire_old_otp(self, expired_otp):
        """Test that old expired OTPs are marked as EXPIRED."""
        otp_service = OTPService()
        otp_service.expire_old_otp(expired_otp.user, ReasonOptions.LOGIN)
        expired_otp.refresh_from_db()
        assert expired_otp.state == OTPState.EXPIRED
