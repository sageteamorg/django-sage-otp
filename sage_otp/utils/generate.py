import base64
import hashlib
import hmac
import struct
import time

from django.conf import settings

from sage_otp.helpers.type_hints import HashAlgorithm

OTP_TOKEN_MIN_LENGTH = getattr(settings, "OTP_TOKEN_MIN_LENGTH", 4)
OTP_TOKEN_MAX_LENGTH = getattr(settings, "OTP_TOKEN_MAX_LENGTH", 8)
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 120)


def generate_totp(
    secret: str,
    digits: int = 6,
    lifetime=OTP_LIFETIME,
    hash_algorithm: HashAlgorithm = hashlib.sha1,
) -> str:
    """Generate a Time-Based One-Time Password (TOTP) based on RFC 6238."""

    if (
        not isinstance(digits, int)
        or not OTP_TOKEN_MIN_LENGTH <= digits <= OTP_TOKEN_MAX_LENGTH
    ):
        raise ValueError("digits must be an integer between 6 and 8 inclusive.")

    if lifetime <= 0:
        raise ValueError("time_step must be a positive integer representing seconds.")

    if not callable(hash_algorithm):
        raise TypeError("hash_algorithm must be a callable hash function.")

    # Decode the secret key from Base32
    try:
        key = base64.b32decode(secret, True)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Invalid secret key.The key must " "be a Base32 encoded string."
        ) from error

    # Calculate the number of time steps since the Unix epoch
    steps_since_epoch = int(time.time() / lifetime)

    # Convert steps to a byte array
    steps_byte = struct.pack(">Q", steps_since_epoch)

    # Generate an HMAC hash of the time steps using the secret key
    hmac_hash = hmac.new(key, steps_byte, hash_algorithm).digest()

    # Use the last 4 bits of the hash as an offset
    offset = hmac_hash[-1] & 0x0F

    # Extract a 4-byte dynamic binary code from the hash at the offset
    dynamic_binary_code = (
        struct.unpack(">I", hmac_hash[offset : offset + 4])[0] & 0x7FFFFFFF
    )

    totp = dynamic_binary_code % (10**digits)

    # Return the TOTP as a zero-padded string
    return f"{totp:0{digits}d}"
