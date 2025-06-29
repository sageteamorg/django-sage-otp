"""
Comprehensive tests for OTP service layer.

This module tests the OTPService class functionality including
OTP creation, verification, expiration, and all business logic.
"""

import pytest
from datetime import timedelta
from unittest.mock import patch, MagicMock
from django.contrib.auth import get_user_model
from django.utils import timezone

from sage_otp.models import OTP
from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import (
    OTPDoesNotExists,
    OTPExpiredException,
    InvalidTokenException,
    UserLockedException,
    RateLimitExceededException,
)
from sage_otp.repository.service.otp import OTPService

User = get_user_model()


@pytest.mark.django_db
class TestOTPServiceUserResolution:
    """Test OTP service user resolution functionality."""

    @pytest.fixture
    def otp_service(self):
        """Create OTP service instance."""
        return OTPService()

    @pytest.fixture
    def user(self):
        """Create a test user."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Add otp_secret field dynamically for testing
        user.otp_secret = None
        user.save()
        return user

    def test_resolve_user_by_id(self, otp_service, user):
        """Test resolving user by ID."""
        resolved_user = otp_service.resolve_user_by_identifier(str(user.id))
        assert resolved_user.id == user.id

    def test_resolve_user_by_email(self, otp_service, user):
        """Test resolving user by email."""
        resolved_user = otp_service.resolve_user_by_identifier(user.email)
        assert resolved_user.id == user.id

    def test_resolve_user_by_username(self, otp_service, user):
        """Test resolving user by username."""
        resolved_user = otp_service.resolve_user_by_identifier(user.username)
        assert resolved_user.id == user.id

    def test_resolve_user_not_found(self, otp_service):
        """Test resolving non-existent user."""
        with pytest.raises(OTPDoesNotExists):
            otp_service.resolve_user_by_identifier("nonexistent")


@pytest.mark.django_db
class TestOTPServiceSecretManagement:
    """Test OTP service secret management functionality."""

    @pytest.fixture
    def otp_service(self):
        """Create OTP service instance."""
        return OTPService()

    @pytest.fixture
    def user(self):
        """Create a test user."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Add otp_secret field dynamically for testing
        user.otp_secret = None
        user.save()
        return user

    def test_get_or_create_user_secret_creates_new(self, otp_service, user):
        """Test that secret is created when user has none."""
        secret = otp_service.get_or_create_user_secret(user)
        
        assert secret is not None
        assert len(secret) > 0
        user.refresh_from_db()
        assert user.otp_secret == secret

    def test_get_or_create_user_secret_returns_existing(self, otp_service, user):
        """Test that existing secret is returned."""
        # Set existing secret
        existing_secret = "EXISTING_SECRET_123"
        user.otp_secret = existing_secret
        user.save()
        
        secret = otp_service.get_or_create_user_secret(user)
        
        assert secret == existing_secret


@pytest.mark.django_db
class TestOTPServiceCleanupOperations:
    """Test OTP service cleanup functionality."""

    @pytest.fixture
    def otp_service(self):
        """Create OTP service instance."""
        return OTPService()

    @pytest.fixture
    def user(self):
        """Create a test user."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Add otp_secret field dynamically for testing
        user.otp_secret = None
        user.save()
        return user

    def test_cleanup_expired_otps_success(self, otp_service, user):
        """Test successful cleanup of expired OTPs."""
        # Create expired OTP
        past_time = timezone.now() - timedelta(seconds=400)
        expired_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            created_at=past_time
        )
        
        # Create active OTP
        active_otp = OTP.objects.create(
            user=user,
            token="654321",
            reason=ReasonOptions.EMAIL_ACTIVATION,
            state=OTPState.ACTIVE
        )
        
        cleaned_count = otp_service.cleanup_expired_otps(user, ReasonOptions.LOGIN)
        
        assert cleaned_count == 1
        expired_otp.refresh_from_db()
        assert expired_otp.state == OTPState.EXPIRED
        
        active_otp.refresh_from_db()
        assert active_otp.state == OTPState.ACTIVE

    def test_cleanup_expired_otps_no_expired(self, otp_service, user):
        """Test cleanup when no expired OTPs exist."""
        cleaned_count = otp_service.cleanup_expired_otps(user, ReasonOptions.LOGIN)
        assert cleaned_count == 0

    def test_unlock_expired_lockouts_success(self, otp_service, user):
        """Test successful unlock of expired lockouts."""
        # Create locked OTP with expired lockout
        past_time = timezone.now() - timedelta(hours=2)
        locked_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.LOCKED,
            lockout_end_time=past_time,
            failed_attempts_count=5
        )
        
        unlocked_count = otp_service.unlock_expired_lockouts(user, ReasonOptions.LOGIN)
        
        assert unlocked_count == 1
        locked_otp.refresh_from_db()
        assert locked_otp.state == OTPState.ACTIVE
        assert locked_otp.failed_attempts_count == 0
        assert locked_otp.lockout_end_time is None


@pytest.mark.django_db
class TestOTPServiceOTPOperations:
    """Test OTP service OTP operations."""

    @pytest.fixture
    def otp_service(self):
        """Create OTP service instance."""
        return OTPService()

    @pytest.fixture
    def user(self):
        """Create a test user."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Add otp_secret field dynamically for testing
        user.otp_secret = None
        user.save()
        return user

    @pytest.fixture
    def active_otp(self, user):
        """Create an active OTP."""
        return OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )

    def test_get_or_create_otp_creates_new(self, otp_service, user):
        """Test get_or_create_otp creates new OTP when none exists."""
        otp, created = otp_service.get_or_create_otp(user.username, ReasonOptions.LOGIN)
        
        assert created is True
        assert otp.user == user
        assert otp.reason == ReasonOptions.LOGIN
        assert otp.state == OTPState.ACTIVE
        assert len(otp.token) >= 6
        assert otp.token.isdigit()

    def test_get_or_create_otp_returns_existing(self, otp_service, user):
        """Test get_or_create_otp returns existing active OTP."""
        # Create existing OTP
        existing_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        otp, created = otp_service.get_or_create_otp(user.username, ReasonOptions.LOGIN)
        
        assert created is False
        assert otp.id == existing_otp.id

    def test_send_otp_success(self, otp_service, user):
        """Test successful OTP sending."""
        result = otp_service.send_otp(user.username, ReasonOptions.LOGIN)
        
        # Should return None if successful (no rate limiting)
        assert result is None
        
        # Verify OTP was created
        otp = OTP.objects.get(user=user, reason=ReasonOptions.LOGIN)
        assert otp.state == OTPState.ACTIVE
        assert otp.last_sent_at is not None

    def test_verify_otp_success(self, otp_service, active_otp):
        """Test successful OTP verification."""
        result = otp_service.verify_otp(
            active_otp.user.username, 
            active_otp.token, 
            ReasonOptions.LOGIN
        )
        
        assert result["token_is_correct"] is True
        active_otp.refresh_from_db()
        assert active_otp.state == OTPState.CONSUMED

    def test_verify_otp_wrong_token(self, otp_service, active_otp):
        """Test OTP verification with wrong token."""
        with pytest.raises(InvalidTokenException):
            otp_service.verify_otp(
                active_otp.user.username,
                "wrong_token",
                ReasonOptions.LOGIN
            )
        
        active_otp.refresh_from_db()
        assert active_otp.failed_attempts_count >= 1

    def test_verify_otp_expired_by_time(self, otp_service, user):
        """Test verification of time-expired OTP."""
        past_time = timezone.now() - timedelta(seconds=400)
        expired_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            created_at=past_time
        )
        
        with pytest.raises(OTPExpiredException):
            otp_service.verify_otp(user.username, "123456", ReasonOptions.LOGIN)

    def test_verify_otp_does_not_exist(self, otp_service, user):
        """Test verification when no OTP exists."""
        with pytest.raises(OTPDoesNotExists):
            otp_service.verify_otp(user.username, "123456", ReasonOptions.LOGIN)

    def test_reset_otp_success(self, otp_service, user):
        """Test successful OTP reset."""
        # Create an OTP first
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            failed_attempts_count=3
        )
        
        reset_otp = otp_service.reset_otp(user.username, ReasonOptions.LOGIN)
        
        assert reset_otp.id == otp.id
        assert reset_otp.failed_attempts_count == 0
        assert reset_otp.state == OTPState.ACTIVE


@pytest.mark.django_db
class TestOTPServiceRateLimiting:
    """Test OTP service rate limiting functionality."""

    @pytest.fixture
    def otp_service(self):
        """Create OTP service instance."""
        return OTPService()

    @pytest.fixture
    def user(self):
        """Create a test user."""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Add otp_secret field dynamically for testing
        user.otp_secret = None
        user.save()
        return user

    def test_check_rate_limits_within_delay(self, otp_service, user):
        """Test rate limiting when within resend delay."""
        recent_time = timezone.now() - timedelta(seconds=30)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            last_sent_at=recent_time
        )
        
        result = otp_service.check_rate_limits(otp)
        
        assert result is not None
        assert result["resend_delay"] is True
        assert "remaining_time" in result

    def test_check_rate_limits_can_resend(self, otp_service, user):
        """Test rate limiting when can resend."""
        past_time = timezone.now() - timedelta(minutes=5)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            last_sent_at=past_time
        )
        
        result = otp_service.check_rate_limits(otp)
        
        assert result is None  # Can resend
