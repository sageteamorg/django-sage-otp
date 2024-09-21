from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from sage_otp.helpers.choices import ReasonOptions
from sage_otp.helpers.exceptions import (
    OTPDoesNotExists,
    OTPException,
    OTPExpiredException,
)
from sage_otp.models import OTP, OTPState
from sage_otp.repository.managers.otp import OTPManager

User = get_user_model()


# Test class for OTPManager
class TestOTPManager:
    """Test cases for the OTPManager class methods."""

    @pytest.fixture
    def create_user(self, db):
        """Fixture to create a test user."""
        return User.objects.create_user(username="testuser", password="password")

    @pytest.fixture
    def create_otp(self, create_user):
        """Fixture to create an active OTP for testing."""
        return OTP.objects.create(
            user=create_user,
            token="123456",
            state=OTPState.ACTIVE,
            reason=ReasonOptions.LOGIN,
        )

    @pytest.fixture
    def expired_otp(self, create_user):
        """Fixture to create an expired OTP."""
        return OTP.objects.create(
            user=create_user,
            token="654321",
            state=OTPState.EXPIRED,
            reason=ReasonOptions.LOGIN,
            created_at=timezone.now() - timedelta(seconds=310),
        )

    def test_get_otp(self, create_user, create_otp):
        """Test retrieving an OTP using get_otp."""
        manager = OTPManager()
        otp = manager.get_otp(create_user.username, ReasonOptions.LOGIN)
        assert otp.token == "123456"
        assert otp.state == OTPState.ACTIVE

    def test_get_otp_does_not_exist(self, create_user):
        """Test that OTPDoesNotExists is raised if no OTP is found."""
        manager = OTPManager()
        with pytest.raises(OTPDoesNotExists):
            manager.get_otp(create_user.username, ReasonOptions.LOGIN)

    def test_get_or_create_otp_create(self, create_user):
        """Test get_or_create_otp when no OTP exists, ensuring one is created."""
        manager = OTPManager()
        otp, created = manager.get_or_create_otp(
            create_user.username, ReasonOptions.LOGIN
        )
        assert created is True
        assert otp.token is not None
        assert otp.state == OTPState.ACTIVE

    def test_reset_otp(self, create_otp):
        """Test resetting an OTP using reset_otp."""
        manager = OTPManager()
        reset_otp = manager.reset_otp(create_otp)
        assert reset_otp.token != "123456"  # Token should be regenerated
        assert reset_otp.failed_attempts_count == 0
        assert reset_otp.state == OTPState.ACTIVE

    def test_check_otp_last_sent_at(self, create_otp):
        """Test that OTP resend check works correctly."""
        manager = OTPManager()
        create_otp.last_sent_at = timezone.now() - timedelta(minutes=1)
        create_otp.save()

        resend_check = manager.check_otp_last_sent_at(create_otp)
        assert resend_check is not None

        create_otp.last_sent_at = timezone.now()
        create_otp.save()

        resend_check = manager.check_otp_last_sent_at(create_otp)
        assert resend_check is not None
        assert resend_check["resend_delay"] is True

    def test_send_otp(self, create_user):
        """Test sending an OTP to a user."""
        manager = OTPManager()
        otp = manager.send_otp(create_user.username, ReasonOptions.LOGIN)
        assert otp is None

    def test_check_otp_valid(self, create_otp):
        """Test that a valid OTP is correctly validated."""
        manager = OTPManager()
        result = manager.check_otp(
            create_otp.user.username, "123456", ReasonOptions.LOGIN
        )
        assert result["token_is_correct"] is True

    def test_check_otp_invalid(self, create_otp):
        """Test that an invalid OTP is handled properly."""
        manager = OTPManager()
        result = manager.check_otp(
            create_otp.user.username, "wrong_token", ReasonOptions.LOGIN
        )
        assert result["token_is_correct"] is False

    def test_check_otp_expired(self, expired_otp):
        """Test that an expired OTP raises OTPExpiredException."""
        manager = OTPManager()
        with pytest.raises(OTPExpiredException):
            manager.check_otp(expired_otp.user.username, "654321", ReasonOptions.LOGIN)
