"""
Configuration module for django-sage-otp.

This module centralizes all OTP-related settings with proper validation
and sensible defaults.
"""

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from typing import Dict, Any


class OTPSettings:
    """
    Centralized OTP settings with validation and defaults.
    """
    
    # Default settings
    DEFAULTS = {
        # Token settings
        'OTP_TOKEN_MIN_LENGTH': 6,
        'OTP_TOKEN_MAX_LENGTH': 8,
        'OTP_DEFAULT_DIGITS': 8,
        
        # Time settings (in seconds)
        'OTP_LIFETIME': 300,  # 5 minutes
        'OTP_TIME_STEP': 30,  # RFC 6238 standard
        'OTP_RESEND_WAIT_TIME': 60,  # 1 minute
        'OTP_LOCKOUT_TIME': 3600,  # 1 hour
        
        # Attempt limits
        'OTP_MAX_FAILED_ATTEMPTS': 5,
        'OTP_MAX_RESEND_ATTEMPTS': 10,
        
        # Security settings
        'OTP_HASH_ALGORITHM': 'sha1',  # sha1, sha256, sha512
        'OTP_SECRET_LENGTH': 20,  # bytes
        
        # Rate limiting
        'OTP_RATE_LIMIT_ENABLED': True,
        'OTP_RATE_LIMIT_WINDOW': 3600,  # 1 hour
        'OTP_RATE_LIMIT_MAX_ATTEMPTS': 10,
        
        # Cleanup settings
        'OTP_AUTO_CLEANUP_ENABLED': True,
        'OTP_CLEANUP_EXPIRED_AFTER': 86400,  # 24 hours
        
        # Logging
        'OTP_LOG_LEVEL': 'INFO',
        'OTP_LOG_FAILED_ATTEMPTS': True,
        'OTP_LOG_SUCCESSFUL_VERIFICATIONS': True,
    }
    
    def __init__(self):
        self._settings = {}
        self._load_settings()
        self._validate_settings()
    
    def _load_settings(self):
        """Load settings from Django settings with defaults."""
        for key, default_value in self.DEFAULTS.items():
            self._settings[key] = getattr(settings, key, default_value)
    
    def _validate_settings(self):
        """Validate OTP settings for consistency and security."""
        errors = []
        
        # Validate token length settings
        min_length = self._settings['OTP_TOKEN_MIN_LENGTH']
        max_length = self._settings['OTP_TOKEN_MAX_LENGTH']
        default_digits = self._settings['OTP_DEFAULT_DIGITS']
        
        if min_length < 4:
            errors.append("OTP_TOKEN_MIN_LENGTH must be at least 4 for security")
        
        if max_length > 12:
            errors.append("OTP_TOKEN_MAX_LENGTH should not exceed 12 for usability")
        
        if min_length > max_length:
            errors.append("OTP_TOKEN_MIN_LENGTH cannot be greater than OTP_TOKEN_MAX_LENGTH")
        
        if not (min_length <= default_digits <= max_length):
            errors.append(f"OTP_DEFAULT_DIGITS ({default_digits}) must be between {min_length} and {max_length}")
        
        # Validate time settings
        if self._settings['OTP_LIFETIME'] < 60:
            errors.append("OTP_LIFETIME should be at least 60 seconds")
        
        if self._settings['OTP_TIME_STEP'] not in [30, 60]:
            errors.append("OTP_TIME_STEP should be 30 or 60 seconds for RFC compliance")
        
        if self._settings['OTP_RESEND_WAIT_TIME'] < 30:
            errors.append("OTP_RESEND_WAIT_TIME should be at least 30 seconds")
        
        # Validate attempt limits
        if self._settings['OTP_MAX_FAILED_ATTEMPTS'] < 3:
            errors.append("OTP_MAX_FAILED_ATTEMPTS should be at least 3")
        
        if self._settings['OTP_MAX_RESEND_ATTEMPTS'] < 5:
            errors.append("OTP_MAX_RESEND_ATTEMPTS should be at least 5")
        
        # Validate hash algorithm
        valid_algorithms = ['sha1', 'sha256', 'sha512']
        if self._settings['OTP_HASH_ALGORITHM'] not in valid_algorithms:
            errors.append(f"OTP_HASH_ALGORITHM must be one of: {valid_algorithms}")
        
        # Validate secret length
        if self._settings['OTP_SECRET_LENGTH'] < 16:
            errors.append("OTP_SECRET_LENGTH should be at least 16 bytes for security")
        
        if errors:
            raise ImproperlyConfigured(
                "Invalid OTP configuration:\n" + "\n".join(f"- {error}" for error in errors)
            )
    
    def __getattr__(self, name: str) -> Any:
        """Get setting value."""
        if name in self._settings:
            return self._settings[name]
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")
    
    def get(self, name: str, default: Any = None) -> Any:
        """Get setting value with default."""
        return self._settings.get(name, default)
    
    def all(self) -> Dict[str, Any]:
        """Get all settings as dictionary."""
        return self._settings.copy()
    
    def update(self, **kwargs):
        """Update settings (for testing purposes)."""
        self._settings.update(kwargs)
        self._validate_settings()


# Global settings instance
otp_settings = OTPSettings()


def get_otp_setting(name: str, default: Any = None) -> Any:
    """
    Convenience function to get OTP setting.
    
    Args:
        name: Setting name
        default: Default value if setting not found
        
    Returns:
        Setting value
    """
    return otp_settings.get(name, default)


def validate_otp_configuration():
    """
    Validate OTP configuration at startup.
    
    This function should be called during Django app initialization
    to ensure all OTP settings are properly configured.
    """
    try:
        otp_settings._validate_settings()
        return True
    except ImproperlyConfigured as e:
        # Log the error or handle it appropriately
        print(f"OTP Configuration Error: {e}")
        return False


# Configuration templates for common use cases
CONFIGURATION_TEMPLATES = {
    'high_security': {
        'OTP_TOKEN_MIN_LENGTH': 8,
        'OTP_DEFAULT_DIGITS': 8,
        'OTP_LIFETIME': 180,  # 3 minutes
        'OTP_MAX_FAILED_ATTEMPTS': 3,
        'OTP_RESEND_WAIT_TIME': 120,  # 2 minutes
        'OTP_LOCKOUT_TIME': 7200,  # 2 hours
        'OTP_HASH_ALGORITHM': 'sha256',
    },
    
    'balanced': {
        'OTP_TOKEN_MIN_LENGTH': 6,
        'OTP_DEFAULT_DIGITS': 6,
        'OTP_LIFETIME': 300,  # 5 minutes
        'OTP_MAX_FAILED_ATTEMPTS': 5,
        'OTP_RESEND_WAIT_TIME': 60,  # 1 minute
        'OTP_LOCKOUT_TIME': 3600,  # 1 hour
        'OTP_HASH_ALGORITHM': 'sha1',
    },
    
    'user_friendly': {
        'OTP_TOKEN_MIN_LENGTH': 6,
        'OTP_DEFAULT_DIGITS': 6,
        'OTP_LIFETIME': 600,  # 10 minutes
        'OTP_MAX_FAILED_ATTEMPTS': 7,
        'OTP_RESEND_WAIT_TIME': 30,  # 30 seconds
        'OTP_LOCKOUT_TIME': 1800,  # 30 minutes
        'OTP_HASH_ALGORITHM': 'sha1',
    }
}


def apply_configuration_template(template_name: str):
    """
    Apply a configuration template.
    
    Args:
        template_name: Name of the template to apply
        
    Raises:
        ValueError: If template name is invalid
    """
    if template_name not in CONFIGURATION_TEMPLATES:
        raise ValueError(f"Unknown template: {template_name}. Available: {list(CONFIGURATION_TEMPLATES.keys())}")
    
    template = CONFIGURATION_TEMPLATES[template_name]
    otp_settings.update(**template)


# Export commonly used settings for backward compatibility
OTP_TOKEN_MIN_LENGTH = otp_settings.OTP_TOKEN_MIN_LENGTH
OTP_TOKEN_MAX_LENGTH = otp_settings.OTP_TOKEN_MAX_LENGTH
OTP_DEFAULT_DIGITS = otp_settings.OTP_DEFAULT_DIGITS
OTP_LIFETIME = otp_settings.OTP_LIFETIME
OTP_TIME_STEP = otp_settings.OTP_TIME_STEP
OTP_MAX_FAILED_ATTEMPTS = otp_settings.OTP_MAX_FAILED_ATTEMPTS
OTP_MAX_RESEND_ATTEMPTS = otp_settings.OTP_MAX_RESEND_ATTEMPTS
OTP_RESEND_WAIT_TIME = otp_settings.OTP_RESEND_WAIT_TIME
OTP_LOCKOUT_TIME = otp_settings.OTP_LOCKOUT_TIME 