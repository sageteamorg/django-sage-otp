"""
Comprehensive tests for OTP manager.

This module tests the OTPManager class functionality including
OTP management, validation, and business logic operations.
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
)
from sage_otp.repository.managers.otp import OTPManager

User = get_user_model()


@pytest.mark.django_db
class TestOTPManagerUserResolution:
    """Test OTP manager user resolution functionality."""

    @pytest.fixture
    def manager(self):
        """Create OTP manager instance."""
        return OTPManager()

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

    def test_resolve_user_by_id(self, manager, user):
        """Test resolving user by ID."""
        resolved_user = manager.resolve_user_by_identifier(str(user.id))
        assert resolved_user.id == user.id

    def test_resolve_user_by_email(self, manager, user):
        """Test resolving user by email."""
        resolved_user = manager.resolve_user_by_identifier(user.email)
        assert resolved_user.id == user.id

    def test_resolve_user_by_username(self, manager, user):
        """Test resolving user by username."""
        resolved_user = manager.resolve_user_by_identifier(user.username)
        assert resolved_user.id == user.id

    def test_resolve_user_not_found(self, manager):
        """Test resolving non-existent user."""
        with pytest.raises(OTPDoesNotExists):
            manager.resolve_user_by_identifier("nonexistent")


@pytest.mark.django_db
class TestOTPManagerSecretGeneration:
    """Test OTP manager secret generation functionality."""

    @pytest.fixture
    def manager(self):
        """Create OTP manager instance."""
        return OTPManager()

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

    def test_get_user_base32_secret_creates_new(self, manager, user):
        """Test that secret is created when user has none."""
        secret = manager.get_user_base32_secret(user)
        
        assert secret is not None
        assert len(secret) > 0
        user.refresh_from_db()
        assert user.otp_secret == secret

    def test_get_user_base32_secret_returns_existing(self, manager, user):
        """Test that existing secret is returned."""
        # Set existing secret
        existing_secret = "EXISTING_SECRET_123"
        user.otp_secret = existing_secret
        user.save()
        
        secret = manager.get_user_base32_secret(user)
        
        assert secret == existing_secret


@pytest.mark.django_db
class TestOTPManagerOTPOperations:
    """Test OTP manager OTP operations."""

    @pytest.fixture
    def manager(self):
        """Create OTP manager instance."""
        return OTPManager()

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

    def test_get_or_create_otp_creates_new(self, manager, user):
        """Test get_or_create_otp creates new OTP when none exists."""
        otp, created = manager.get_or_create_otp(user.username, ReasonOptions.LOGIN)
        
        assert created is True
        assert otp.user == user
        assert otp.reason == ReasonOptions.LOGIN
        assert otp.state == OTPState.ACTIVE
        assert len(otp.token) >= 6
        assert otp.token.isdigit()

    def test_get_or_create_otp_returns_existing(self, manager, user):
        """Test get_or_create_otp returns existing active OTP."""
        # Create existing OTP
        existing_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE
        )
        
        otp, created = manager.get_or_create_otp(user.username, ReasonOptions.LOGIN)
        
        assert created is False
        assert otp.id == existing_otp.id
        assert otp.token == "123456"

    def test_get_otp_success(self, manager, active_otp):
        """Test successful OTP retrieval."""
        otp = manager.get_otp(active_otp.user.username, ReasonOptions.LOGIN)
        
        assert otp.id == active_otp.id
        assert otp.token == "123456"
        assert otp.state == OTPState.ACTIVE

    def test_get_otp_not_found(self, manager, user):
        """Test get_otp when no OTP exists."""
        with pytest.raises(OTPDoesNotExists):
            manager.get_otp(user.username, ReasonOptions.LOGIN)

    def test_reset_otp_success(self, manager, active_otp):
        """Test successful OTP reset."""
        old_token = active_otp.token
        active_otp.failed_attempts_count = 3
        active_otp.save()
        
        reset_otp = manager.reset_otp(active_otp)
        
        assert reset_otp.id == active_otp.id
        assert reset_otp.token != old_token  # New token generated
        assert reset_otp.failed_attempts_count == 0
        assert reset_otp.state == OTPState.ACTIVE

    def test_check_otp_valid_token_success(self, manager, active_otp):
        """Test successful OTP verification."""
        result = manager.check_otp(
            active_otp.user.username, 
            active_otp.token, 
            ReasonOptions.LOGIN
        )
        
        assert result["token_is_correct"] is True
        active_otp.refresh_from_db()
        assert active_otp.state == OTPState.CONSUMED

    def test_check_otp_invalid_token(self, manager, active_otp):
        """Test OTP verification with wrong token."""
        with pytest.raises(Exception):  # Should raise some exception for wrong token
            manager.check_otp(
                active_otp.user.username,
                "wrong_token",
                ReasonOptions.LOGIN
            )
        
        active_otp.refresh_from_db()
        assert active_otp.failed_attempts_count >= 1

    def test_check_otp_expired_raises_exception(self, manager, user):
        """Test check_otp with expired OTP."""
        past_time = timezone.now() - timedelta(seconds=400)
        expired_otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            created_at=past_time
        )
        
        with pytest.raises(OTPExpiredException):
            manager.check_otp(user.username, "123456", ReasonOptions.LOGIN)


@pytest.mark.django_db
class TestOTPManagerResendOperations:
    """Test OTP manager resend functionality."""

    @pytest.fixture
    def manager(self):
        """Create OTP manager instance."""
        return OTPManager()

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

    def test_check_otp_last_sent_at_can_resend(self, manager, user):
        """Test that OTP can be resent after wait time."""
        past_time = timezone.now() - timedelta(minutes=5)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            last_sent_at=past_time
        )
        
        result = manager.check_otp_last_sent_at(otp)
        assert result is None  # Can resend

    def test_check_otp_last_sent_at_within_delay(self, manager, user):
        """Test that OTP cannot be resent within wait time."""
        recent_time = timezone.now() - timedelta(seconds=30)
        otp = OTP.objects.create(
            user=user,
            token="123456",
            reason=ReasonOptions.LOGIN,
            state=OTPState.ACTIVE,
            last_sent_at=recent_time
        )
        
        result = manager.check_otp_last_sent_at(otp)
        assert result is not None
        assert result["resend_delay"] is True
        assert "resend_release_time_remaining" in result

    def test_send_otp_success(self, manager, user):
        """Test successful OTP sending."""
        result = manager.send_otp(user.username, ReasonOptions.LOGIN)
        
        # Should return None if successful (no delay)
        assert result is None
        
        # Verify OTP was created
        otp = OTP.objects.get(user=user, reason=ReasonOptions.LOGIN)
        assert otp.state == OTPState.ACTIVE
        assert otp.last_sent_at is not None
