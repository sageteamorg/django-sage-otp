import pytest

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import InvalidStateException, OTPExpiredException


# Test class for ReasonOptions
class TestReasonOptions:
    """Test cases for the ReasonOptions enumeration."""

    def test_email_activation(self):
        """Test the value of EMAIL_ACTIVATION in ReasonOptions."""
        assert ReasonOptions.EMAIL_ACTIVATION == "email_activation"

    def test_login(self):
        """Test the value of LOGIN in ReasonOptions."""
        assert ReasonOptions.LOGIN == "login"

    def test_reset_password(self):
        """Test the value of RESET_PASSWORD in ReasonOptions."""
        assert ReasonOptions.RESET_PASSWORD == "reset_password"

    def test_forget_password(self):
        """Test the value of FORGET_PASSWORD in ReasonOptions."""
        assert ReasonOptions.FORGET_PASSWORD == "forget_password"

    def test_phone_number_activation(self):
        """Test the value of PHONE_NUMBER_ACTIVATION in ReasonOptions."""
        assert ReasonOptions.PHONE_NUMBER_ACTIVATION == "phone_number_activation"


# Test class for OTPState
class TestOTPState:
    """Test cases for the OTPState enumeration and state transitions."""

    def test_active_state(self):
        """Test the value of the ACTIVE state."""
        assert OTPState.ACTIVE == "Active"

    def test_consumed_state(self):
        """Test the value of the CONSUMED state."""
        assert OTPState.CONSUMED == "Consumed"

    def test_expired_state(self):
        """Test the value of the EXPIRED state."""
        assert OTPState.EXPIRED == "Expired"

    def test_validate_transition_valid(self):
        """Test a valid state transition from ACTIVE to CONSUMED."""
        OTPState.validate_transition(OTPState.ACTIVE, OTPState.CONSUMED)

    def test_validate_transition_invalid(self):
        """Test an invalid state transition and ensure it raises
        InvalidStateException.
        """
        with pytest.raises(InvalidStateException):
            OTPState.validate_transition(OTPState.CONSUMED, OTPState.ACTIVE)

    def test_to_consumed_transition(self):
        """Test the static method for transitioning to the CONSUMED state."""
        new_state = OTPState.to_consumed(OTPState.ACTIVE)
        assert new_state == OTPState.CONSUMED

    def test_to_expired_transition(self):
        """Test the static method for transitioning to the EXPIRED state."""
        new_state = OTPState.to_expired(OTPState.ACTIVE)
        assert new_state == OTPState.EXPIRED


# Test class for custom exceptions
class TestOTPExceptions:
    """Test cases for custom exceptions in the OTP system."""

    def test_invalid_state_exception(self):
        """Test that InvalidStateException raises with the correct message."""
        with pytest.raises(InvalidStateException) as exc_info:
            raise InvalidStateException("Invalid state transition")
        assert str(exc_info.value) == "['Invalid state transition']"

    def test_otp_expired_exception(self):
        """Test that OTPExpiredException raises with the correct message."""
        with pytest.raises(OTPExpiredException) as exc_info:
            raise OTPExpiredException("OTP has expired")
        assert str(exc_info.value) == "['OTP has expired']"
