"""
Comprehensive tests for OTP models.

This module tests all model functionality including validation,
state transitions, and edge cases.
"""

import pytest
from datetime import timedelta
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone

from sage_otp.models import OTP
from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import InvalidStateException

User = get_user_model()


@pytest.mark.django_db
class TestOTPModelCreation:
    """Test OTP model creation and validation."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_otp_creation_success(self, user):
        """Test successful OTP creation with valid data."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        assert otp.user == user
        assert otp.token == "123456"
        assert otp.reason == ReasonOptions.LOGIN
        assert otp.state == OTPState.ACTIVE
        assert otp.failed_attempts_count == 0
        assert otp.resend_requests_count == 0
        assert otp.last_sent_at is None
        assert otp.lockout_end_time is None

    def test_otp_str_representation(self, user):
        """Test OTP string representation."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        expected = f"OTP for {user} ({ReasonOptions.LOGIN}) - {OTPState.ACTIVE}"
        assert str(otp) == expected

    def test_otp_repr_representation(self, user):
        """Test OTP repr representation."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        expected = f"<OTP: user={user.id}, reason={ReasonOptions.LOGIN}, state={OTPState.ACTIVE}>"
        assert repr(otp) == expected


@pytest.mark.django_db
class TestOTPModelValidation:
    """Test OTP model validation rules."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_token_format_validation_success(self, user):
        """Test that numeric tokens pass validation."""
        otp = OTP(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN
        )
        otp.full_clean()  # Should not raise

    def test_token_length_validation_success(self, user):
        """Test that tokens within length limits pass validation."""
        # Test minimum length
        otp_min = OTP(
            user=user,
            token="123456",  # 6 digits (minimum)
            reason=ReasonOptions.LOGIN
        )
        otp_min.full_clean()
        
        # Test maximum length
        otp_max = OTP(
            user=user,
            token="12345678",  # 8 digits (maximum)
            reason=ReasonOptions.LOGIN
        )
        otp_max.full_clean()

    def test_model_clean_validation_success(self, user):
        """Test that model clean validation passes with valid data."""
        otp = OTP(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            failed_attempts_count=2,
            resend_requests_count=3
        )
        otp.clean()  # Should not raise


@pytest.mark.django_db
class TestOTPModelStateManagement:
    """Test OTP state management and transitions."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    @pytest.fixture
    def active_otp(self, user):
        """Create an active OTP."""
        return OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )

    def test_state_transition_active_to_consumed_success(self, active_otp):
        """Test successful transition from ACTIVE to CONSUMED."""
        active_otp.update_state(OTPState.CONSUMED)
        assert active_otp.state == OTPState.CONSUMED

    def test_state_transition_active_to_expired_success(self, active_otp):
        """Test successful transition from ACTIVE to EXPIRED."""
        active_otp.update_state(OTPState.EXPIRED)
        assert active_otp.state == OTPState.EXPIRED

    def test_state_transition_active_to_locked_success(self, active_otp):
        """Test successful transition from ACTIVE to LOCKED."""
        active_otp.update_state(OTPState.LOCKED)
        assert active_otp.state == OTPState.LOCKED

    def test_state_transition_consumed_to_active_failure(self, active_otp):
        """Test that transition from CONSUMED to ACTIVE fails."""
        active_otp.update_state(OTPState.CONSUMED)
        
        with pytest.raises(InvalidStateException):
            active_otp.update_state(OTPState.ACTIVE)

    def test_state_transition_locked_to_active_success(self, active_otp):
        """Test successful transition from LOCKED to ACTIVE."""
        active_otp.update_state(OTPState.LOCKED)
        active_otp.update_state(OTPState.ACTIVE)
        assert active_otp.state == OTPState.ACTIVE


@pytest.mark.django_db
class TestOTPModelValidationMethods:
    """Test OTP validation and status checking methods."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_is_valid_token_success(self, user):
        """Test valid token validation."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        is_valid, state = otp.is_valid_token("123456")
        assert is_valid is True
        assert state == OTPState.ACTIVE

    def test_is_valid_token_wrong_token(self, user):
        """Test validation with wrong token."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        is_valid, state = otp.is_valid_token("654321")
        assert is_valid is False
        assert state == OTPState.ACTIVE

    def test_is_valid_token_expired_otp(self, user):
        """Test validation with expired OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        # Manually update created_at to past time to simulate expiration
        past_time = timezone.now() - timedelta(seconds=400)
        OTP.objects.filter(id=otp.id).update(created_at=past_time)
        otp.refresh_from_db()
        
        # The OTP should be detected as expired and marked as such
        is_valid, state = otp.is_valid_token("123456")
        # The method returns the detected state, not the current state
        assert is_valid is False
        # Since it detects expiration, it should return EXPIRED state
        assert state == OTPState.EXPIRED

    def test_is_valid_token_consumed_otp(self, user):
        """Test validation with consumed OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.CONSUMED
        )
        
        is_valid, state = otp.is_valid_token("123456")
        assert is_valid is False
        assert state == OTPState.CONSUMED


@pytest.mark.django_db
class TestOTPModelStatusChecks:
    """Test OTP status checking methods."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_is_consumed_true(self, user):
        """Test is_consumed returns True for consumed OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.CONSUMED
        )
        
        assert otp.is_consumed() is True

    def test_is_consumed_false(self, user):
        """Test is_consumed returns False for non-consumed OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        assert otp.is_consumed() is False

    def test_is_expired_true_by_state(self, user):
        """Test is_expired returns True for OTP with EXPIRED state."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.EXPIRED
        )
        
        assert otp.is_expired() is True

    def test_is_expired_true_by_time(self, user):
        """Test is_expired returns True for time-expired OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        # Manually update created_at to past time to simulate expiration
        past_time = timezone.now() - timedelta(seconds=400)
        OTP.objects.filter(id=otp.id).update(created_at=past_time)
        otp.refresh_from_db()
        
        assert otp.is_expired() is True

    def test_is_expired_false(self, user):
        """Test is_expired returns False for non-expired OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        assert otp.is_expired() is False

    def test_is_locked_true(self, user):
        """Test is_locked returns True for locked OTP."""
        future_time = timezone.now() + timedelta(hours=1)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.LOCKED,
            lockout_end_time=future_time
        )
        
        assert otp.is_locked() is True

    def test_is_locked_false_no_lockout_time(self, user):
        """Test is_locked returns False when no lockout time is set."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.LOCKED
        )
        
        # Without lockout_end_time, even LOCKED state should return False
        assert otp.is_locked() is False


@pytest.mark.django_db
class TestOTPModelLimitChecks:
    """Test OTP limit checking methods."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_is_token_limit_exceeded_true(self, user):
        """Test is_token_limit_exceeded returns True when limit exceeded."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            failed_attempts_count=5  # Assuming 5 is the limit
        )
        
        assert otp.is_token_limit_exceeded() is True

    def test_is_token_limit_exceeded_false(self, user):
        """Test is_token_limit_exceeded returns False when under limit."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            failed_attempts_count=2
        )
        
        assert otp.is_token_limit_exceeded() is False

    def test_is_resend_limit_exceeded_true(self, user):
        """Test is_resend_limit_exceeded returns True when limit exceeded."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            resend_requests_count=10  # Assuming 10 is the limit
        )
        
        assert otp.is_resend_limit_exceeded() is True

    def test_is_resend_limit_exceeded_false(self, user):
        """Test is_resend_limit_exceeded returns False when under limit."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            resend_requests_count=5
        )
        
        assert otp.is_resend_limit_exceeded() is False


@pytest.mark.django_db
class TestOTPModelResendMethods:
    """Test OTP resend-related methods."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_can_resend_true_no_last_sent(self, user):
        """Test can_resend returns True when never sent."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN
        )
        
        assert otp.can_resend() is True

    def test_can_resend_true_wait_time_passed(self, user):
        """Test can_resend returns True when wait time has passed."""
        past_time = timezone.now() - timedelta(minutes=2)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            last_sent_at=past_time
        )
        
        assert otp.can_resend() is True

    def test_can_resend_false_within_wait_time(self, user):
        """Test can_resend returns False when within wait time."""
        recent_time = timezone.now() - timedelta(seconds=30)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            last_sent_at=recent_time
        )
        
        assert otp.can_resend() is False

    def test_get_resend_wait_time_zero_no_last_sent(self, user):
        """Test get_resend_wait_time returns 0 when never sent."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN
        )
        
        assert otp.get_resend_wait_time() == 0

    def test_get_resend_wait_time_zero_can_resend(self, user):
        """Test get_resend_wait_time returns 0 when can resend."""
        past_time = timezone.now() - timedelta(minutes=2)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            last_sent_at=past_time
        )
        
        assert otp.get_resend_wait_time() == 0

    def test_get_resend_wait_time_positive_within_wait(self, user):
        """Test get_resend_wait_time returns positive value when within wait time."""
        recent_time = timezone.now() - timedelta(seconds=30)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            last_sent_at=recent_time
        )
        
        wait_time = otp.get_resend_wait_time()
        assert wait_time > 0
        assert wait_time <= 60  # Should be less than or equal to wait time


@pytest.mark.django_db
class TestOTPModelTimeMethods:
    """Test OTP time-related methods."""

    @pytest.fixture
    def user(self):
        """Create a test user."""
        return User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )

    def test_get_time_remaining_positive(self, user):
        """Test get_time_remaining returns positive value for fresh OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        remaining = otp.get_time_remaining()
        assert remaining > 0
        assert remaining <= 300  # Should be less than or equal to lifetime

    def test_get_time_remaining_zero_expired(self, user):
        """Test get_time_remaining returns 0 for expired OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        # Manually update created_at to past time to simulate expiration
        past_time = timezone.now() - timedelta(seconds=400)
        OTP.objects.filter(id=otp.id).update(created_at=past_time)
        otp.refresh_from_db()
        
        assert otp.get_time_remaining() == 0

    def test_get_lockout_remaining_time_positive(self, user):
        """Test get_lockout_remaining_time returns positive value for locked OTP."""
        future_time = timezone.now() + timedelta(hours=1)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.LOCKED,
            lockout_end_time=future_time
        )
        
        remaining = otp.get_lockout_remaining_time()
        assert remaining > 0
        assert remaining <= 3600  # Should be less than or equal to 1 hour

    def test_get_lockout_remaining_time_zero_not_locked(self, user):
        """Test get_lockout_remaining_time returns 0 for non-locked OTP."""
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        assert otp.get_lockout_remaining_time() == 0
