"""
Comprehensive tests for OTP utilities.

This module tests utility functions including token generation,
TOTP generation, secret generation, and validation.
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from sage_otp.utils.generate import (
    generate_otp_token,
    generate_totp,
    generate_secure_secret,
    verify_totp,
)


class TestOTPTokenGeneration:
    """Test OTP token generation functionality."""

    def test_generate_otp_token_default_length(self):
        """Test OTP token generation with default length."""
        token = generate_otp_token()
        
        assert len(token) == 8  # Default length
        assert token.isdigit()
        assert int(token) >= 0

    def test_generate_otp_token_custom_length(self):
        """Test OTP token generation with custom length."""
        for length in [6, 7, 8]:
            token = generate_otp_token(digits=length)
            assert len(token) == length
            assert token.isdigit()

    def test_generate_otp_token_minimum_length(self):
        """Test OTP token generation with minimum allowed length."""
        token = generate_otp_token(digits=6)
        assert len(token) == 6
        assert token.isdigit()

    def test_generate_otp_token_maximum_length(self):
        """Test OTP token generation with maximum allowed length."""
        token = generate_otp_token(digits=8)
        assert len(token) == 8
        assert token.isdigit()

    def test_generate_otp_token_invalid_length_too_small(self):
        """Test OTP token generation fails with length too small."""
        with pytest.raises(ValueError) as exc_info:
            generate_otp_token(digits=5)
        assert "digits must be an integer between" in str(exc_info.value)

    def test_generate_otp_token_invalid_length_too_large(self):
        """Test OTP token generation fails with length too large."""
        with pytest.raises(ValueError) as exc_info:
            generate_otp_token(digits=9)
        assert "digits must be an integer between" in str(exc_info.value)

    def test_generate_otp_token_invalid_type(self):
        """Test OTP token generation fails with invalid type."""
        with pytest.raises(ValueError):
            generate_otp_token(digits="6")  # type: ignore

    def test_generate_otp_token_uniqueness(self):
        """Test that generated tokens are reasonably unique."""
        tokens = set()
        for _ in range(100):
            token = generate_otp_token()
            tokens.add(token)
        
        # Should have generated mostly unique tokens
        assert len(tokens) > 90  # Allow for some duplicates due to randomness

    def test_generate_otp_token_leading_zeros(self):
        """Test that tokens can have leading zeros and maintain length."""
        # Generate many tokens to increase chance of getting leading zeros
        tokens = []
        for _ in range(1000):
            token = generate_otp_token(digits=6)
            tokens.append(token)
            assert len(token) == 6
            assert token.isdigit()
        
        # At least some should have leading zeros
        leading_zero_tokens = [t for t in tokens if t.startswith('0')]
        assert len(leading_zero_tokens) > 0


class TestTOTPGeneration:
    """Test TOTP token generation functionality."""

    def test_generate_totp_token_with_secret(self):
        """Test TOTP token generation with secret."""
        secret = "JBSWY3DPEHPK3PXP"  # Base32 encoded secret
        token = generate_totp(secret)
        
        assert len(token) == 8  # Default length
        assert token.isdigit()

    def test_generate_totp_token_custom_length(self):
        """Test TOTP token generation with custom length."""
        secret = "JBSWY3DPEHPK3PXP"
        
        for length in [6, 7, 8]:
            token = generate_totp(secret, digits=length)
            assert len(token) == length
            assert token.isdigit()

    def test_generate_totp_token_custom_time_step(self):
        """Test TOTP token generation with custom time step."""
        secret = "JBSWY3DPEHPK3PXP"
        
        # Generate tokens with different time steps
        token_30 = generate_totp(secret, time_step=30)
        token_60 = generate_totp(secret, time_step=60)
        
        assert len(token_30) == 8
        assert len(token_60) == 8
        assert token_30.isdigit()
        assert token_60.isdigit()

    def test_generate_totp_token_with_timestamp(self):
        """Test TOTP token generation with specific timestamp."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890  # Fixed timestamp
        
        token = generate_totp(secret, current_time=timestamp)
        
        assert len(token) == 8
        assert token.isdigit()

    def test_generate_totp_token_deterministic(self):
        """Test that TOTP generation is deterministic for same inputs."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890
        
        token1 = generate_totp(secret, current_time=timestamp)
        token2 = generate_totp(secret, current_time=timestamp)
        
        assert token1 == token2

    def test_generate_totp_token_different_times(self):
        """Test that TOTP tokens differ for different time steps."""
        secret = "JBSWY3DPEHPK3PXP"
        
        # Generate tokens for different time periods
        # Use times that are clearly in the same 30-second window
        base_time = 1000000000
        # Round down to nearest 30-second boundary
        window_start = (base_time // 30) * 30
        
        token1 = generate_totp(secret, current_time=window_start)
        token2 = generate_totp(secret, current_time=window_start + 15)  # Same window
        
        # Should be the same within same 30-second window
        assert token1 == token2
        
        # But different for different windows
        token3 = generate_totp(secret, current_time=window_start + 30)  # Next window
        assert token1 != token3

    def test_generate_totp_token_invalid_digits(self):
        """Test TOTP generation fails with invalid digit count."""
        secret = "JBSWY3DPEHPK3PXP"
        
        with pytest.raises(ValueError):
            generate_totp(secret, digits=5)
        
        with pytest.raises(ValueError):
            generate_totp(secret, digits=9)

    def test_generate_totp_token_invalid_time_step(self):
        """Test TOTP generation fails with invalid time step."""
        secret = "JBSWY3DPEHPK3PXP"
        
        with pytest.raises(ValueError):
            generate_totp(secret, time_step=0)
        
        with pytest.raises(ValueError):
            generate_totp(secret, time_step=-30)

    def test_generate_totp_token_empty_secret(self):
        """Test TOTP generation fails with empty secret."""
        with pytest.raises(ValueError, match="Invalid secret key"):
            generate_totp("")

    def test_generate_totp_token_invalid_secret(self):
        """Test TOTP generation fails with invalid base32 secret."""
        with pytest.raises(Exception):  # Should raise base32 decode error
            generate_totp("INVALID_SECRET!")


class TestTOTPValidation:
    """Test TOTP token validation functionality."""

    def test_validate_totp_token_success(self):
        """Test successful TOTP token validation."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1234567890
        
        # Generate a token
        token = generate_totp(secret, current_time=timestamp)
        
        # Validate the same token
        is_valid = verify_totp(secret, token, current_time=timestamp)
        assert is_valid is True

    def test_validate_totp_token_failure(self):
        """Test TOTP token validation failure."""
        secret = "JBSWY3DPEHPK3PXP"
        
        # Validate wrong token
        is_valid = verify_totp(secret, "123456")
        assert is_valid is False

    def test_validate_totp_token_time_window(self):
        """Test TOTP validation within time window."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1000000000
        
        # Generate token for specific time
        token = generate_totp(secret, current_time=timestamp)
        
        # Should be valid within the same time window
        is_valid = verify_totp(secret, token, current_time=timestamp)
        assert is_valid is True
        
        # Should be valid within window tolerance
        is_valid = verify_totp(secret, token, current_time=timestamp + 15)
        assert is_valid is True

    def test_validate_totp_token_with_window(self):
        """Test TOTP validation with custom window."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1000000000
        
        # Generate token for specific time
        token = generate_totp(secret, current_time=timestamp)
        
        # Should be valid with larger window
        is_valid = verify_totp(secret, token, current_time=timestamp + 60, window=2)
        assert is_valid is True
        
        # Should be invalid with smaller window
        is_valid = verify_totp(secret, token, current_time=timestamp + 60, window=0)
        assert is_valid is False

    def test_validate_totp_token_custom_parameters(self):
        """Test TOTP validation with custom parameters."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1000000000
        digits = 6
        time_step = 60
        
        # Generate token with custom parameters
        token = generate_totp(
            secret, 
            digits=digits, 
            time_step=time_step, 
            current_time=timestamp
        )
        
        # Validate with same parameters
        is_valid = verify_totp(
            secret, 
            token, 
            digits=digits, 
            time_step=time_step, 
            current_time=timestamp
        )
        assert is_valid is True

    def test_validate_totp_token_parameter_mismatch(self):
        """Test TOTP validation fails with parameter mismatch."""
        secret = "JBSWY3DPEHPK3PXP"
        timestamp = 1000000000
        
        # Generate token with 8 digits
        token = generate_totp(secret, digits=8, current_time=timestamp)
        
        # Validate with 6 digits should fail
        is_valid = verify_totp(secret, token, digits=6, current_time=timestamp)
        assert is_valid is False


class TestSecretGeneration:
    """Test secret generation functionality."""

    def test_generate_secret_default_length(self):
        """Test secret generation with default length."""
        secret = generate_secure_secret()
        
        assert len(secret) > 0
        assert isinstance(secret, str)

    def test_generate_secret_custom_length(self):
        """Test secret generation with custom length."""
        # Note: generate_secure_secret doesn't take length parameter
        # It generates a fixed 160-bit (20 byte) secret
        secret = generate_secure_secret()
        
        assert len(secret) > 0
        assert isinstance(secret, str)

    def test_generate_secret_uniqueness(self):
        """Test that generated secrets are unique."""
        secrets = set()
        for _ in range(10):
            secret = generate_secure_secret()
            secrets.add(secret)
        
        # Should have generated unique secrets
        assert len(secrets) == 10

    def test_generate_secret_base32_format(self):
        """Test that generated secret is valid Base32."""
        secret = generate_secure_secret()
        
        # Should be valid Base32 (only contains A-Z, 2-7)
        import base64
        try:
            decoded = base64.b32decode(secret)
            assert len(decoded) == 20  # 160 bits = 20 bytes
        except Exception:
            assert False, "Generated secret is not valid Base32"

    def test_generate_secret_invalid_length(self):
        """Test secret generation with invalid length."""
        # generate_secure_secret doesn't take parameters, so this test doesn't apply
        pass

    def test_generate_secret_minimum_length(self):
        """Test secret generation with minimum length."""
        secret = generate_secure_secret()
        
        # Should be at least 32 characters (160 bits in Base32)
        assert len(secret) >= 32

    def test_generate_secret_entropy(self):
        """Test that generated secrets have good entropy."""
        secrets = []
        for _ in range(100):
            secret = generate_secure_secret()
            secrets.append(secret)
        
        # Check that we have variety in the generated secrets
        unique_chars = set()
        for secret in secrets:
            unique_chars.update(secret)
        
        # Should use most of the Base32 alphabet
        assert len(unique_chars) >= 20  # At least 20 different characters

    @patch('secrets.token_bytes')
    def test_generate_secret_uses_secure_random(self, mock_token_bytes):
        """Test that secret generation uses secure random."""
        mock_token_bytes.return_value = b'test_secret_bytes_20'
        
        secret = generate_secure_secret()
        
        mock_token_bytes.assert_called_once_with(20)
        assert secret is not None


class TestUtilityIntegration:
    """Test integration between different utility functions."""

    def test_otp_totp_integration(self):
        """Test that OTP and TOTP functions work together."""
        # Generate simple OTP token
        otp_token = generate_otp_token()
        assert len(otp_token) == 8
        assert otp_token.isdigit()
        
        # Generate TOTP token
        secret = generate_secure_secret()
        totp_token = generate_totp(secret)
        assert len(totp_token) == 8
        assert totp_token.isdigit()
        
        # They should be different types of tokens
        assert otp_token != totp_token

    def test_totp_generation_validation_cycle(self):
        """Test complete TOTP generation and validation cycle."""
        secret = generate_secure_secret()
        timestamp = 1234567890
        
        # Generate token
        token = generate_totp(secret, current_time=timestamp)
        
        # Validate token
        is_valid = verify_totp(secret, token, current_time=timestamp)
        assert is_valid is True
        
        # Validate wrong token
        is_valid = verify_totp(secret, "000000", current_time=timestamp)
        assert is_valid is False

    def test_time_based_token_evolution(self):
        """Test that TOTP tokens change over time."""
        secret = generate_secure_secret()
        
        # Generate tokens for different time periods
        # Use times that are clearly in the same 30-second window
        base_time = 1000000000
        window_start = (base_time // 30) * 30
        
        token1 = generate_totp(secret, current_time=window_start)
        token2 = generate_totp(secret, current_time=window_start + 15)  # Same window
        token3 = generate_totp(secret, current_time=window_start + 30)  # Different window
        
        # Tokens in same window should be the same
        assert token1 == token2
        
        # Tokens in different windows should be different
        assert token1 != token3

    def test_parameter_consistency(self):
        """Test that parameters are consistent across functions."""
        secret = generate_secure_secret()
        timestamp = 1000000000
        digits = 6
        time_step = 60
        
        # Generate with custom parameters
        token = generate_totp(
            secret, 
            digits=digits, 
            time_step=time_step, 
            current_time=timestamp
        )
        
        # Validate with same parameters
        is_valid = verify_totp(
            secret, 
            token, 
            digits=digits, 
            time_step=time_step, 
            current_time=timestamp
        )
        assert is_valid is True
        
        # Validate with different parameters should fail
        is_valid = verify_totp(
            secret, 
            token, 
            digits=8,  # Different digits
            time_step=time_step, 
            current_time=timestamp
        )
        assert is_valid is False

    @patch('time.time')
    def test_current_time_usage(self, mock_time):
        """Test that functions use current time when not specified."""
        mock_time.return_value = 1234567890
        secret = generate_secure_secret()
        
        # Generate token without specifying time
        token1 = generate_totp(secret)
        
        # Generate token with explicit time
        token2 = generate_totp(secret, current_time=1234567890)
        
        # Should be the same
        assert token1 == token2 