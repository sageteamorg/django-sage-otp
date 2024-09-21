"""
This module defines a hierarchy of exceptions specifically tailored for handling
errors related to One-Time Password (OTP) operations within a Django application.

These exceptions extend from Django's ValidationError class, providing a structured
approach to capturing and reporting various OTP-related issues, such as validation
failures, expiry, and transmission errors.

Hierarchy:
- ValidationError
  - OTPException
    - InvalidOTPException
    - OTPExpiredException
    - MaxAttemptsExceededException
    - OTPAlreadyUsedException
    - AlreadyExistsException
    - OTPDoesNotExists
    - InvalidStateException
    - OTPSendFailedException
    - UserLockedException
    - OTPConfigurationException

This structured exception hierarchy facilitates precise error handling and reporting
in systems that utilize OTPs for authentication, authorization, or other security
measures.
"""

from django.core.exceptions import ValidationError


class OTPException(ValidationError):
    """Base exception class for OTP-related errors."""

    default_code = "otp_error"
    default_message = "An error occurred with the OTP process."

    def __init__(self, message=None, code=None, params=None):
        if message is None:
            message = self.default_message
        if code is None:
            code = self.default_code
        super().__init__(message, code=code, params=params)


class InvalidTokenException(OTPException):
    """Exception for when an Token is invalid."""

    default_code = "invalid_otp"
    default_message = "The provided Token is invalid."


class OTPExpiredException(OTPException):
    """Exception for when an OTP has expired."""

    default_code = "otp_expired"
    default_message = "The OTP has expired."


class MaxAttemptsExceededException(OTPException):
    """
    Exception for when the maximum number of OTP verification attempts has been
    exceeded.
    """

    default_code = "max_attempts_exceeded"
    default_message = "The maximum number of verification attempts has been exceeded."


class OTPAlreadyUsedException(OTPException):
    """Exception for when an OTP has already been used."""

    default_code = "otp_already_used"
    default_message = "This OTP has already been used."


class AlreadyExistsException(OTPException):
    """Exception for when a violation of a uniqueness constraint occurs."""

    default_code = "already_exists"
    default_message = "The entity already exists with the specified unique attribute."


class OTPDoesNotExists(OTPException):
    """Exception for when a violation of a uniqueness constraint occurs."""

    default_code = "does_not_exists"
    default_message = "The entity does not exists."


class InvalidStateException(OTPException):
    """Exception for when an attempt is made to transition to an invalid state."""

    default_code = "invalid_state"
    default_message = "The requested state transition is invalid."


class OTPSendFailedException(OTPException):
    """Exception for when an OTP fails to send to the user."""

    default_code = "otp_send_failed"
    default_message = "Failed to send the OTP."


class UserLockedException(OTPException):
    """
    Exception for when a user is locked out from receiving or using OTPs due to too
    many failed attempts.
    """

    default_code = "user_locked"
    default_message = "The user is locked due to too many failed attempts."


class OTPConfigurationException(OTPException):
    """Exception for when there is a configuration error in the OTP system."""

    default_code = "otp_configuration_error"
    default_message = "There is a configuration error with the OTP system."
