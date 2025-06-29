import base64
import hashlib
import hmac
import struct
import time
import secrets

from django.conf import settings

from sage_otp.helpers.type_hints import HashAlgorithm

# Improved default settings for better security
OTP_TOKEN_MIN_LENGTH = getattr(settings, "OTP_TOKEN_MIN_LENGTH", 6)
OTP_TOKEN_MAX_LENGTH = getattr(settings, "OTP_TOKEN_MAX_LENGTH", 8)
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 300)  # 5 minutes default
OTP_TIME_STEP = getattr(settings, "OTP_TIME_STEP", 30)  # RFC 6238 standard


def generate_otp_token(digits: int = 8) -> str:
    """
    Generate a random OTP token (not time-based).

    Args:
        digits (int): Number of digits in the OTP (6-8)

    Returns:
        str: Generated OTP token

    Raises:
        ValueError: If digits parameter is invalid
    """
    if (
        not isinstance(digits, int)
        or not OTP_TOKEN_MIN_LENGTH <= digits <= OTP_TOKEN_MAX_LENGTH
    ):
        raise ValueError(
            f"digits must be an integer between {OTP_TOKEN_MIN_LENGTH} and {OTP_TOKEN_MAX_LENGTH} inclusive."
        )

    # Generate a random token with the specified number of digits
    max_value = 10**digits - 1
    token = secrets.randbelow(max_value + 1)
    
    # Return as zero-padded string
    return f"{token:0{digits}d}"


def generate_secure_secret() -> str:
    """
    Generate a cryptographically secure Base32 secret for TOTP.

    Returns:
        str: A Base32-encoded secret suitable for TOTP generation.
    """
    # Generate 20 bytes (160 bits) of entropy as recommended by RFC 6238
    secret_bytes = secrets.token_bytes(20)
    return base64.b32encode(secret_bytes).decode("ascii")


def generate_totp(
    secret: str,
    digits: int = 8,  # Increased default for better security
    time_step: int = OTP_TIME_STEP,
    hash_algorithm: HashAlgorithm = hashlib.sha1,
    current_time: int = None,
) -> str:
    """
    Generate a Time-Based One-Time Password (TOTP) based on RFC 6238.

    Args:
        secret (str): Base32-encoded secret key
        digits (int): Number of digits in the OTP (6-8)
        time_step (int): Time step in seconds (default: 30 as per RFC 6238)
        hash_algorithm: Hash algorithm to use (default: SHA1)
        current_time (int): Current time in seconds (for testing purposes)

    Returns:
        str: Generated TOTP token

    Raises:
        ValueError: If parameters are invalid
        TypeError: If hash_algorithm is not callable
    """
    if (
        not isinstance(digits, int)
        or not OTP_TOKEN_MIN_LENGTH <= digits <= OTP_TOKEN_MAX_LENGTH
    ):
        raise ValueError(
            f"digits must be an integer between {OTP_TOKEN_MIN_LENGTH} and {OTP_TOKEN_MAX_LENGTH} inclusive."
        )

    if not isinstance(time_step, int) or time_step <= 0:
        raise ValueError("time_step must be a positive integer representing seconds.")

    if not callable(hash_algorithm):
        raise TypeError("hash_algorithm must be a callable hash function.")

    # Decode the secret key from Base32
    try:
        key = base64.b32decode(secret, True)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Invalid secret key. The key must be a Base32 encoded string."
        ) from error

    # Use provided time or current time
    if current_time is None:
        current_time = int(time.time())

    # Calculate the number of time steps since the Unix epoch (RFC 6238)
    time_counter = current_time // time_step

    # Convert counter to a byte array (big-endian 64-bit integer)
    counter_bytes = struct.pack(">Q", time_counter)

    # Generate an HMAC hash of the counter using the secret key
    hmac_hash = hmac.new(key, counter_bytes, hash_algorithm).digest()

    # Dynamic truncation as per RFC 6238
    offset = hmac_hash[-1] & 0x0F

    # Extract a 4-byte dynamic binary code from the hash at the offset
    dynamic_binary_code = (
        struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF
    )

    # Generate the OTP
    totp = dynamic_binary_code % (10**digits)

    # Return the TOTP as a zero-padded string
    return f"{totp:0{digits}d}"


def verify_totp(
    secret: str,
    token: str,
    digits: int = 8,
    time_step: int = OTP_TIME_STEP,
    window: int = 1,
    hash_algorithm: HashAlgorithm = hashlib.sha1,
    current_time: int = None,
) -> bool:
    """
    Verify a TOTP token with time window tolerance.

    Args:
        secret (str): Base32-encoded secret key
        token (str): Token to verify
        digits (int): Number of digits in the OTP
        time_step (int): Time step in seconds
        window (int): Number of time steps to check before and after current time
        hash_algorithm: Hash algorithm to use
        current_time (int): Current time in seconds (for testing purposes)

    Returns:
        bool: True if token is valid, False otherwise
    """
    if current_time is None:
        current_time = int(time.time())

    # Check current time and surrounding windows
    for i in range(-window, window + 1):
        test_time = current_time + (i * time_step)
        expected_token = generate_totp(
            secret=secret,
            digits=digits,
            time_step=time_step,
            hash_algorithm=hash_algorithm,
            current_time=test_time,
        )
        if expected_token == token:
            return True

    return False
