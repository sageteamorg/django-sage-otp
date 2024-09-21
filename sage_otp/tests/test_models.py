from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from sage_otp.helpers.choices import ReasonOptions
from sage_otp.models import OTP, OTPState

User = get_user_model()


@pytest.mark.django_db
class TestOTPModel:
    """Test cases for the OTP model."""

    @pytest.fixture
    def create_user(self):
        """Fixture to create a user."""
        return User.objects.create_user(username="testuser", password="password")

    @pytest.fixture
    def create_otp(self, create_user):
        """Fixture to create an OTP instance."""
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

    def test_is_valid_token(self, create_otp):
        """Test that OTP token validation works correctly."""
        is_valid, state = create_otp.is_valid_token("123456")
        assert is_valid is True
        assert state == OTPState.ACTIVE

    def test_is_valid_token_invalid(self, create_otp):
        """Test that an invalid OTP token is correctly identified."""
        is_valid, state = create_otp.is_valid_token("wrong_token")
        assert is_valid is False
        assert state == OTPState.ACTIVE

    def test_is_consumed(self, create_otp):
        """Test that OTP consumption status is checked correctly."""
        assert create_otp.is_consumed() is False
        create_otp.state = OTPState.CONSUMED
        create_otp.save()
        assert create_otp.is_consumed() is True

    def test_is_expired(self, expired_otp):
        """Test that expired OTP is identified correctly."""
        assert expired_otp.is_expired() is True

    def test_is_expired_not_expired(self, create_otp):
        """Test that active OTP is not marked as expired."""
        assert create_otp.is_expired() is False

    def test_is_token_limit_exceeds(self, create_otp):
        """Test that failed attempts limit is checked correctly."""
        assert create_otp.is_token_limit_exceeds() is False
        create_otp.failed_attempts_count = 3  # Assuming 3 is the max in settings
        assert create_otp.is_token_limit_exceeds() is True

    def test_update_state(self, create_otp):
        """Test that OTP state updates correctly."""
        assert create_otp.state == OTPState.ACTIVE
        create_otp.update_state(OTPState.CONSUMED)
        assert create_otp.state == OTPState.CONSUMED

    def test_get_time_elapsed(self, create_otp):
        """Test that time remaining until OTP expiration is calculated correctly."""
        remaining_time = create_otp.get_time_elapsed()
        assert remaining_time > 0

    def test_get_time_elapsed_expired(self, expired_otp):
        """Test that expired OTP returns 0 time remaining."""
        remaining_time = expired_otp.get_time_elapsed()
        assert remaining_time == 0
