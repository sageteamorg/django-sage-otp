"""
This module defines a hierarchy of exceptions specifically tailored for handling
errors related to One-Time Password (OTP) operations within a Django application.

These exceptions provide a structured approach to capturing and reporting various 
OTP-related issues, such as validation failures, expiry, and transmission errors.

Hierarchy:
- OTPException (base)
  - OTPValidationException (ValidationError subclass for form validation)
    - InvalidTokenException
    - OTPExpiredException
    - OTPAlreadyUsedException
  - OTPSecurityException (for security-related issues)
    - MaxAttemptsExceededException
    - UserLockedException
    - RateLimitExceededException
  - OTPStateException (for state management issues)
    - InvalidStateException
  - OTPNotFoundException (for missing OTP issues)
    - OTPDoesNotExists
  - OTPConfigurationException (for configuration issues)
  - OTPSendFailedException (for delivery issues)

This structured exception hierarchy facilitates precise error handling and reporting
in systems that utilize OTPs for authentication, authorization, or other security
measures.
"""

from django.core.exceptions import ValidationError


class OTPException(Exception):
    """Base exception class for all OTP-related errors."""

    default_code = "otp_error"
    default_message = "An error occurred with the OTP process."

    def __init__(self, message=None, code=None, params=None):
        if message is None:
            message = self.default_message
        self.code = code or self.default_code
        self.params = params or {}
        super().__init__(message)


class OTPValidationException(ValidationError, OTPException):
    """Base exception for OTP validation errors that should integrate with Django forms."""

    def __init__(self, message=None, code=None, params=None):
        OTPException.__init__(self, message, code, params)
        ValidationError.__init__(self, message, code=code, params=params)


class OTPSecurityException(OTPException):
    """Base exception for security-related OTP errors."""
    
    default_code = "otp_security_error"
    default_message = "A security-related OTP error occurred."


class OTPStateException(OTPException):
    """Base exception for OTP state management errors."""
    
    default_code = "otp_state_error"
    default_message = "An OTP state management error occurred."


class OTPNotFoundException(OTPException):
    """Base exception for OTP not found errors."""
    
    default_code = "otp_not_found"
    default_message = "The requested OTP was not found."


# Validation Exceptions
class InvalidTokenException(OTPValidationException):
    """Exception for when a token is invalid."""

    default_code = "invalid_token"
    default_message = "The provided token is invalid."


class OTPExpiredException(OTPValidationException):
    """Exception for when an OTP has expired."""

    default_code = "otp_expired"
    default_message = "The OTP has expired."


class OTPAlreadyUsedException(OTPValidationException):
    """Exception for when an OTP has already been used."""

    default_code = "otp_already_used"
    default_message = "This OTP has already been used."


# Security Exceptions
class MaxAttemptsExceededException(OTPSecurityException):
    """
    Exception for when the maximum number of OTP verification attempts has been
    exceeded.
    """

    default_code = "max_attempts_exceeded"
    default_message = "The maximum number of verification attempts has been exceeded."


class UserLockedException(OTPSecurityException):
    """
    Exception for when a user is locked out from receiving or using OTPs due to too
    many failed attempts.
    """

    default_code = "user_locked"
    default_message = "The user is locked due to too many failed attempts."


class RateLimitExceededException(OTPSecurityException):
    """Exception for when rate limiting is triggered."""
    
    default_code = "rate_limit_exceeded"
    default_message = "Rate limit exceeded. Please try again later."


# State Management Exceptions
class InvalidStateException(OTPStateException):
    """Exception for when an attempt is made to transition to an invalid state."""

    default_code = "invalid_state"
    default_message = "The requested state transition is invalid."


# Not Found Exceptions
class OTPDoesNotExists(OTPNotFoundException):
    """Exception for when an OTP does not exist."""

    default_code = "otp_does_not_exist"
    default_message = "The OTP does not exist."


class AlreadyExistsException(OTPException):
    """Exception for when a violation of a uniqueness constraint occurs."""

    default_code = "already_exists"
    default_message = "The entity already exists with the specified unique attribute."


# Configuration and System Exceptions
class OTPConfigurationException(OTPException):
    """Exception for when there is a configuration error in the OTP system."""

    default_code = "otp_configuration_error"
    default_message = "There is a configuration error with the OTP system."


class OTPSendFailedException(OTPException):
    """Exception for when an OTP fails to send to the user."""

    default_code = "otp_send_failed"
    default_message = "Failed to send the OTP."


# Utility function for creating exceptions with context
def create_otp_exception(
    exception_class: type,
    message: str = None,
    code: str = None,
    params: dict = None,
    **kwargs
) -> OTPException:
    """
    Utility function to create OTP exceptions with additional context.
    
    Args:
        exception_class: The exception class to instantiate
        message: Custom error message
        code: Error code
        params: Additional parameters
        **kwargs: Additional context data
        
    Returns:
        OTPException: Configured exception instance
    """
    if params is None:
        params = {}
    params.update(kwargs)
    
    return exception_class(message=message, code=code, params=params)
