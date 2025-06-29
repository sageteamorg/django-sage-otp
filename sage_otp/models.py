"""
Module: models.py.

This module contains the definition of the OTP model,
which represents a one-time password token associated with a user.

Classes:
    OTP: Model representing a one-time password token.

Attributes:
    User: Django user model representing the user associated with the token.
"""

from datetime import timedelta

from django.conf import settings
from django.core.validators import MaxLengthValidator, MinLengthValidator, RegexValidator
from django.db import models
from django.utils import timezone as tz
from django.utils.translation import gettext_lazy as _
from sage_tools.mixins.models import TimeStampMixin

from .helpers.choices import OTPState, ReasonOptions

# Configuration with better defaults
OTP_TOKEN_MIN_LENGTH = getattr(settings, "OTP_TOKEN_MIN_LENGTH", 6)
OTP_TOKEN_MAX_LENGTH = getattr(settings, "OTP_TOKEN_MAX_LENGTH", 8)
OTP_MAX_FAILED_ATTEMPTS = getattr(settings, "OTP_MAX_FAILED_ATTEMPTS", 5)
OTP_MAX_RESEND_ATTEMPTS = getattr(settings, "OTP_MAX_RESEND_ATTEMPTS", 10)
OTP_RESEND_WAIT_TIME = getattr(settings, "OTP_RESEND_WAIT_TIME", 60)  # 1 minute
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 300)  # 5 minutes
OTP_LOCKOUT_TIME = getattr(settings, "OTP_LOCKOUT_TIME", 3600)  # 1 hour


class OTP(TimeStampMixin):
    """
    Represents an OTP (One-Time Password) entity with state management and
    validation logic.
    
    This model handles the storage and basic validation of OTP tokens.
    Business logic is handled separately in the service layer.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("User"),
        on_delete=models.CASCADE,
        related_name="otps",  # Changed to plural for clarity
        help_text=_("The user who owns this OTP."),
        db_comment="Reference to the user associated with this OTP.",
        db_index=True,  # Add index for performance
    )
    
    token = models.CharField(
        _("Token"),
        max_length=OTP_TOKEN_MAX_LENGTH,
        validators=[
            MinLengthValidator(OTP_TOKEN_MIN_LENGTH),
            MaxLengthValidator(OTP_TOKEN_MAX_LENGTH),
            RegexValidator(
                regex=r'^\d+$',
                message=_('Token must contain only digits.'),
                code='invalid_token_format'
            ),
        ],
        help_text=_("Automatically generated OTP sent to the user."),
        db_comment="Numeric OTP token generated for the user.",
    )
    
    failed_attempts_count = models.PositiveSmallIntegerField(
        _("Failed Attempts"),
        default=0,
        help_text=_("Tracks the number of incorrect OTP submissions."),
        db_comment="Counter for incorrect OTP attempts by the user.",
    )
    
    resend_requests_count = models.PositiveSmallIntegerField(
        _("Resend Requests"),
        default=0,
        help_text=_("Tracks the number of OTP resend requests."),
        db_comment="Counter for OTP resend attempts by the user.",
    )
    
    state = models.CharField(
        _("Status"),
        max_length=20,  # Increased to accommodate longer state names
        choices=OTPState.choices,
        default=OTPState.ACTIVE,
        help_text=_("Current state of the OTP (e.g., active, consumed, expired)."),
        db_comment="Current state of the OTP, indicating if it's active, consumed, expired, or locked.",
        db_index=True,  # Add index for performance
    )
    
    reason = models.CharField(
        _("Reason"),
        max_length=50,  # Increased to accommodate longer reason names
        choices=ReasonOptions.choices,
        help_text=_("The reason why the OTP was generated."),
        db_comment="Reason for OTP generation, such as login or password reset.",
        db_index=True,  # Add index for performance
    )
    
    last_sent_at = models.DateTimeField(
        _("Last Sent At"),
        null=True,
        blank=True,
        default=None,
        help_text=_("The time when the OTP was last sent"),
        db_comment="Timestamp of the last OTP send attempt",
    )

    lockout_end_time = models.DateTimeField(
        _("Lockout End Time"),
        null=True,
        blank=True,
        default=None,
        help_text=_("The time until which OTP is locked out."),
        db_comment="Timestamp until which this OTP cannot be retried after exceeding max attempts.",
    )

    # Remove the business logic layer reference - this should be handled in services
    objects = models.Manager()

    class Meta:
        verbose_name = _("OTP")
        verbose_name_plural = _("OTPs")
        
        # Improved constraints and indexes
        constraints = [
            models.UniqueConstraint(
                fields=["user", "reason"],
                condition=models.Q(state=OTPState.ACTIVE),
                name="unique_active_user_reason",
            ),
            models.CheckConstraint(
                check=models.Q(failed_attempts_count__gte=0),
                name="non_negative_failed_attempts",
            ),
            models.CheckConstraint(
                check=models.Q(resend_requests_count__gte=0),
                name="non_negative_resend_requests",
            ),
        ]
        
        indexes = [
            models.Index(fields=['user', 'state', 'reason'], name='otp_user_state_reason_idx'),
            models.Index(fields=['created_at', 'state'], name='otp_created_state_idx'),
            models.Index(fields=['lockout_end_time'], name='otp_lockout_end_idx'),
        ]
        
        # Default ordering
        ordering = ['-created_at']

    def clean(self):
        """Custom validation for the model."""
        super().clean()
        
        # Validate failed attempts don't exceed maximum
        if self.failed_attempts_count > OTP_MAX_FAILED_ATTEMPTS:
            from django.core.exceptions import ValidationError
            raise ValidationError({
                'failed_attempts_count': _('Failed attempts cannot exceed maximum allowed.')
            })
            
        # Validate resend requests don't exceed maximum
        if self.resend_requests_count > OTP_MAX_RESEND_ATTEMPTS:
            from django.core.exceptions import ValidationError
            raise ValidationError({
                'resend_requests_count': _('Resend requests cannot exceed maximum allowed.')
            })

    def is_valid_token(self, token: str) -> tuple[bool, OTPState]:
        """
        Check if the provided token is valid for this OTP.
        
        Args:
            token (str): The token to validate
            
        Returns:
            tuple[bool, OTPState]: (is_valid, current_state)
        """
        if self.is_expired():
            return False, OTPState.EXPIRED
        if self.is_consumed():
            return False, OTPState.CONSUMED
        if self.is_locked():
            return False, OTPState.LOCKED
        if token != self.token:
            return False, OTPState.ACTIVE
        return True, OTPState.ACTIVE

    def is_locked(self) -> bool:
        """Check if the OTP is currently locked."""
        if self.state != OTPState.LOCKED:
            return False
        if not self.lockout_end_time:
            return False
        return self.lockout_end_time > tz.now()

    def is_consumed(self) -> bool:
        """Check if the OTP has been consumed."""
        return self.state == OTPState.CONSUMED

    def is_expired(self) -> bool:
        """Check if the OTP has expired."""
        if self.state == OTPState.EXPIRED:
            return True
            
        token_expire_at = self.created_at + timedelta(seconds=OTP_LIFETIME)
        return token_expire_at < tz.now()

    def is_token_limit_exceeded(self) -> bool:
        """Check if the failed attempts limit has been exceeded."""
        return self.failed_attempts_count >= OTP_MAX_FAILED_ATTEMPTS

    def is_resend_limit_exceeded(self) -> bool:
        """Check if the resend requests limit has been exceeded."""
        return self.resend_requests_count >= OTP_MAX_RESEND_ATTEMPTS

    def can_resend(self) -> bool:
        """Check if the OTP can be resent based on time constraints."""
        if not self.last_sent_at:
            return True
        
        wait_until = self.last_sent_at + timedelta(seconds=OTP_RESEND_WAIT_TIME)
        return tz.now() >= wait_until

    def get_resend_wait_time(self) -> int:
        """Get the remaining wait time in seconds before OTP can be resent."""
        if not self.last_sent_at or self.can_resend():
            return 0
        
        wait_until = self.last_sent_at + timedelta(seconds=OTP_RESEND_WAIT_TIME)
        remaining = (wait_until - tz.now()).total_seconds()
        return max(0, int(remaining))

    def update_state(self, new_state: OTPState) -> None:
        """
        Update the state of the OTP with validation.
        
        Args:
            new_state (OTPState): The new state to transition to
            
        Raises:
            InvalidStateException: If the transition is not allowed
        """
        OTPState.validate_transition(self.state, new_state)
        self.state = new_state
        self.save(update_fields=['state', 'modified_at'])

    def get_time_remaining(self) -> int:
        """Get the remaining time in seconds before the OTP expires."""
        if self.is_expired():
            return 0

        token_expire_at = self.created_at + timedelta(seconds=OTP_LIFETIME)
        now = tz.now()

        if now >= token_expire_at:
            return 0

        remaining_seconds = (token_expire_at - now).total_seconds()
        return max(0, int(remaining_seconds))

    def get_lockout_remaining_time(self) -> int:
        """Get the remaining lockout time in seconds."""
        if not self.is_locked():
            return 0
        
        remaining = (self.lockout_end_time - tz.now()).total_seconds()
        return max(0, int(remaining))

    def __str__(self) -> str:
        return f"OTP for {self.user} ({self.reason}) - {self.state}"

    def __repr__(self) -> str:
        return f"<OTP: user={self.user.id}, reason={self.reason}, state={self.state}>"
