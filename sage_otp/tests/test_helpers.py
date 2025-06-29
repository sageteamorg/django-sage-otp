"""
Comprehensive tests for OTP helpers.

This module tests helper classes, choices, and exceptions.
"""

import pytest

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import (
    InvalidStateException, 
    OTPExpiredException,
    OTPDoesNotExists,
    InvalidTokenException,
    UserLockedException,
    RateLimitExceededException,
)


class TestReasonOptions:
    """Test cases for the ReasonOptions enumeration."""

    def test_email_activation_value(self):
        """Test the value of EMAIL_ACTIVATION in ReasonOptions."""
        assert ReasonOptions.EMAIL_ACTIVATION == "email_activation"

    def test_login_value(self):
        """Test the value of LOGIN in ReasonOptions."""
        assert ReasonOptions.LOGIN == "login"

    def test_reset_password_value(self):
        """Test the value of RESET_PASSWORD in ReasonOptions."""
        assert ReasonOptions.RESET_PASSWORD == "reset_password"

    def test_forget_password_value(self):
        """Test the value of FORGET_PASSWORD in ReasonOptions."""
        assert ReasonOptions.FORGET_PASSWORD == "forget_password"

    def test_phone_number_activation_value(self):
        """Test the value of PHONE_NUMBER_ACTIVATION in ReasonOptions."""
        assert ReasonOptions.PHONE_NUMBER_ACTIVATION == "phone_number_activation"

    def test_all_choices_exist(self):
        """Test that all expected choices exist."""
        expected_choices = [
            "email_activation",
            "login", 
            "reset_password",
            "forget_password",
            "phone_number_activation"
        ]
        
        for choice in expected_choices:
            assert hasattr(ReasonOptions, choice.upper())


class TestOTPState:
    """Test cases for the OTPState enumeration and state transitions."""

    def test_active_state_value(self):
        """Test the value of the ACTIVE state."""
        assert OTPState.ACTIVE == "Active"

    def test_consumed_state_value(self):
        """Test the value of the CONSUMED state."""
        assert OTPState.CONSUMED == "Consumed"

    def test_expired_state_value(self):
        """Test the value of the EXPIRED state."""
        assert OTPState.EXPIRED == "Expired"

    def test_locked_state_value(self):
        """Test the value of the LOCKED state."""
        assert OTPState.LOCKED == "Locked"

    def test_all_states_exist(self):
        """Test that all expected states exist."""
        expected_states = ["Active", "Consumed", "Expired", "Locked"]
        
        for state in expected_states:
            assert hasattr(OTPState, state.upper())

    def test_validate_transition_active_to_consumed_success(self):
        """Test valid transition from ACTIVE to CONSUMED."""
        # Should not raise exception
        OTPState.validate_transition(OTPState.ACTIVE, OTPState.CONSUMED)

    def test_validate_transition_active_to_expired_success(self):
        """Test valid transition from ACTIVE to EXPIRED."""
        # Should not raise exception
        OTPState.validate_transition(OTPState.ACTIVE, OTPState.EXPIRED)

    def test_validate_transition_active_to_locked_success(self):
        """Test valid transition from ACTIVE to LOCKED."""
        # Should not raise exception
        OTPState.validate_transition(OTPState.ACTIVE, OTPState.LOCKED)

    def test_validate_transition_locked_to_active_success(self):
        """Test valid transition from LOCKED to ACTIVE."""
        # Should not raise exception
        OTPState.validate_transition(OTPState.LOCKED, OTPState.ACTIVE)

    def test_validate_transition_locked_to_expired_success(self):
        """Test valid transition from LOCKED to EXPIRED."""
        # Should not raise exception
        OTPState.validate_transition(OTPState.LOCKED, OTPState.EXPIRED)

    def test_validate_transition_consumed_to_active_failure(self):
        """Test invalid transition from CONSUMED to ACTIVE."""
        with pytest.raises(InvalidStateException):
            OTPState.validate_transition(OTPState.CONSUMED, OTPState.ACTIVE)

    def test_validate_transition_expired_to_active_failure(self):
        """Test invalid transition from EXPIRED to ACTIVE."""
        with pytest.raises(InvalidStateException):
            OTPState.validate_transition(OTPState.EXPIRED, OTPState.ACTIVE)

    def test_validate_transition_consumed_to_locked_failure(self):
        """Test invalid transition from CONSUMED to LOCKED."""
        with pytest.raises(InvalidStateException):
            OTPState.validate_transition(OTPState.CONSUMED, OTPState.LOCKED)

    def test_to_consumed_transition_success(self):
        """Test the static method for transitioning to the CONSUMED state."""
        new_state = OTPState.to_consumed(OTPState.ACTIVE)
        assert new_state == OTPState.CONSUMED

    def test_to_consumed_transition_failure(self):
        """Test to_consumed fails for invalid current state."""
        with pytest.raises(InvalidStateException):
            OTPState.to_consumed(OTPState.EXPIRED)

    def test_to_expired_transition_success(self):
        """Test the static method for transitioning to the EXPIRED state."""
        new_state = OTPState.to_expired(OTPState.ACTIVE)
        assert new_state == OTPState.EXPIRED

    def test_to_expired_transition_from_locked_success(self):
        """Test to_expired transition from LOCKED state."""
        new_state = OTPState.to_expired(OTPState.LOCKED)
        assert new_state == OTPState.EXPIRED

    def test_to_locked_transition_success(self):
        """Test the static method for transitioning to the LOCKED state."""
        new_state = OTPState.to_locked(OTPState.ACTIVE)
        assert new_state == OTPState.LOCKED

    def test_to_locked_transition_failure(self):
        """Test to_locked fails for invalid current state."""
        with pytest.raises(InvalidStateException):
            OTPState.to_locked(OTPState.CONSUMED)

    def test_to_active_transition_success(self):
        """Test the static method for transitioning to the ACTIVE state."""
        new_state = OTPState.to_active(OTPState.LOCKED)
        assert new_state == OTPState.ACTIVE

    def test_to_active_transition_failure(self):
        """Test to_active fails for invalid current state."""
        with pytest.raises(InvalidStateException):
            OTPState.to_active(OTPState.CONSUMED)


class TestOTPExceptions:
    """Test cases for custom exceptions in the OTP system."""

    def test_invalid_state_exception_creation(self):
        """Test that InvalidStateException can be created with message."""
        message = "Invalid state transition"
        exception = InvalidStateException(message)
        assert str(exception) == message

    def test_invalid_state_exception_raise(self):
        """Test that InvalidStateException raises with the correct message."""
        with pytest.raises(InvalidStateException) as exc_info:
            raise InvalidStateException("Invalid state transition")
        assert "Invalid state transition" in str(exc_info.value)

    def test_otp_expired_exception_creation(self):
        """Test that OTPExpiredException can be created with message."""
        message = "OTP has expired"
        exception = OTPExpiredException(message)
        # ValidationError stores messages in a list, so we need to check differently
        assert message in str(exception)

    def test_otp_expired_exception_raise(self):
        """Test that OTPExpiredException raises with the correct message."""
        with pytest.raises(OTPExpiredException) as exc_info:
            raise OTPExpiredException("OTP has expired")
        assert "OTP has expired" in str(exc_info.value)

    def test_otp_does_not_exist_exception_creation(self):
        """Test that OTPDoesNotExists can be created with message."""
        message = "OTP does not exist"
        exception = OTPDoesNotExists(message)
        assert str(exception) == message

    def test_otp_does_not_exist_exception_raise(self):
        """Test that OTPDoesNotExists raises with the correct message."""
        with pytest.raises(OTPDoesNotExists) as exc_info:
            raise OTPDoesNotExists("OTP does not exist")
        assert "OTP does not exist" in str(exc_info.value)

    def test_invalid_token_exception_creation(self):
        """Test that InvalidTokenException can be created with message."""
        message = "Invalid token provided"
        exception = InvalidTokenException(message)
        # ValidationError stores messages in a list, so we need to check differently
        assert message in str(exception)

    def test_invalid_token_exception_raise(self):
        """Test that InvalidTokenException raises with the correct message."""
        with pytest.raises(InvalidTokenException) as exc_info:
            raise InvalidTokenException("Invalid token provided")
        assert "Invalid token provided" in str(exc_info.value)

    def test_user_locked_exception_creation(self):
        """Test that UserLockedException can be created with message."""
        message = "User is locked due to too many failed attempts"
        exception = UserLockedException(message)
        assert str(exception) == message

    def test_user_locked_exception_raise(self):
        """Test that UserLockedException raises with the correct message."""
        with pytest.raises(UserLockedException) as exc_info:
            raise UserLockedException("User is locked")
        assert "User is locked" in str(exc_info.value)

    def test_rate_limit_exceeded_exception_creation(self):
        """Test that RateLimitExceededException can be created with message."""
        message = "Rate limit exceeded"
        exception = RateLimitExceededException(message)
        assert str(exception) == message

    def test_rate_limit_exceeded_exception_raise(self):
        """Test that RateLimitExceededException raises with the correct message."""
        with pytest.raises(RateLimitExceededException) as exc_info:
            raise RateLimitExceededException("Rate limit exceeded")
        assert "Rate limit exceeded" in str(exc_info.value)

    def test_exception_inheritance(self):
        """Test that all exceptions inherit from Exception."""
        assert issubclass(InvalidStateException, Exception)
        assert issubclass(OTPExpiredException, Exception)
        assert issubclass(OTPDoesNotExists, Exception)
        assert issubclass(InvalidTokenException, Exception)
        assert issubclass(UserLockedException, Exception)
        assert issubclass(RateLimitExceededException, Exception)

    def test_exception_with_multiple_messages(self):
        """Test that exceptions can handle multiple messages."""
        # Test with OTPDoesNotExists which doesn't inherit from ValidationError
        exception = OTPDoesNotExists("First error", params={"key": "value"})
        assert "First error" in str(exception)

    def test_exception_with_no_message(self):
        """Test that exceptions work with no message."""
        exception = OTPDoesNotExists()
        assert str(exception) != ""  # Should have default message
