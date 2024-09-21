"""
Module: otp.py.

This module contains the definition of the OTP model,
which represents a one-time password token associated with a user.

Classes:
    OTP: Model representing a one-time password token.

Attributes:
    User: Django user model representing the user associated with the token.
"""

from datetime import timedelta

from django.conf import settings
from django.core.validators import MaxLengthValidator, MinLengthValidator
from django.db import models
from django.utils import timezone as tz
from django.utils.translation import gettext_lazy as _
from sage_tools.mixins.models import TimeStampMixin

from .helpers.choices import OTPState, ReasonOptions
from .repository.managers.otp import OtpBusinessLogicLayer

OTP_TOKEN_MIN_LENGTH = getattr(settings, "OTP_TOKEN_MIN_LENGTH", 4)
OTP_TOKEN_MAX_LENGTH = getattr(settings, "OTP_TOKEN_MAX_LENGTH", 8)
OTP_MAX_FAILED_ATTEMPTS = getattr(settings, "OTP_MAX_FAILED_ATTEMPTS", 3)
OTP_RESEND_WAIT_TIME = getattr(settings, "OTP_RESEND_WAIT_TIME", 2)
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 120)


class OTP(TimeStampMixin):
    """
    Represents an OTP (One-Time Password) entity with state management and
    validation logic.
    """

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("User"),
        on_delete=models.CASCADE,
        related_name="otp",
        help_text=_("The user who owns this OTP."),
        db_comment="Reference to the user associated with this OTP.",
    )
    token = models.CharField(
        _("Token"),
        max_length=8,
        validators=[
            MinLengthValidator(OTP_TOKEN_MIN_LENGTH),
            MaxLengthValidator(OTP_TOKEN_MAX_LENGTH),
        ],
        help_text=_("Automatically generated OTP sent to the user."),
        db_comment="6-digit OTP generated for the user.",
    )
    failed_attempts_count = models.PositiveSmallIntegerField(
        _("Number of Wrong Submits"),
        default=0,
        help_text=_("Tracks the number of incorrect OTP submissions."),
        db_comment="Counter for incorrect OTP attempts by the user.",
    )
    resend_requests_count = models.PositiveSmallIntegerField(
        _("Number of requests count"),
        default=0,
        help_text=_("Tracks the number of requests OTP counts."),
        db_comment="Counter for resend OTP attempts by the user.",
    )
    state = models.CharField(
        _("Status"),
        max_length=10,
        choices=OTPState.choices,
        default=OTPState.ACTIVE,
        help_text=_("Current state of the OTP (e.g., active, consumed, expired)."),
        db_comment="Current state of the OTP, indicating if it's active, consumed, expired, or locked.",
    )
    reason = models.CharField(
        _("Reason"),
        max_length=40,
        choices=ReasonOptions.choices,
        help_text=_("The reason why the OTP was generated."),
        db_comment="Reason for OTP generation, such as login or password reset.",
    )
    last_sent_at = models.DateTimeField(
        _("last_sent_at"),
        null=True,
        blank=True,
        default=None,
        help_text=_("The Time when the OTP was last sent"),
        db_comment="Time of the Otp send last time",
    )

    bll = OtpBusinessLogicLayer()
    objects = models.Manager()

    class Meta:
        verbose_name = _("OTP")
        verbose_name_plural = _("OTP")
        constraints = [
            models.UniqueConstraint(
                fields=["user", "token", "reason"],
                condition=models.Q(state=OTPState.ACTIVE),
                name="unique_active_user_token",
            )
        ]

    def is_valid_token(self, token: str) -> tuple[bool, OTPState]:
        if self.is_expired():
            return False, OTPState.EXPIRED
        if self.is_consumed():
            return False, OTPState.CONSUMED
        if token != self.token:
            return False, OTPState.ACTIVE
        return True, OTPState.ACTIVE

    def is_consumed(self):
        if self.state == OTPState.CONSUMED:
            return True
        return False

    def is_expired(self) -> bool:
        token_expire_at = self.created_at + timedelta(seconds=OTP_LIFETIME)

        if self.state == OTPState.EXPIRED or (
            self.state != OTPState.EXPIRED and token_expire_at < tz.now()
        ):
            return True
        return False

    def is_token_limit_exceeds(self):
        if self.failed_attempts_count >= OTP_MAX_FAILED_ATTEMPTS:
            return True
        return False

    def update_state(self, new_state: OTPState):
        """
        Updates the state of the OTP to a new specified state after validating
        the transition according to predefined rules.

        This method ensures that state transitions are valid and
        consistent with the allowed transitions defined in the OTPState class.

        The method leverages the OTPState.validate_transition static method to
        check if the proposed state change is permissible
        f the transition is valid, it updates the
        state of the OTP instance and persists the change to the database.
        """
        OTPState.validate_transition(self.state, new_state)

        self.state = new_state
        self.save()

    def get_time_elapsed(self) -> int:
        """Calculates the remaining time in seconds before the OTP expires."""
        token_expire_at = self.created_at + timedelta(seconds=OTP_LIFETIME)
        now = tz.now()

        if self.is_expired() or now >= token_expire_at:
            return 0

        remaining_seconds = (token_expire_at - now).total_seconds()
        return max(0, int(remaining_seconds))

    def __str__(self):
        return f"{self.user}"

    def __repr__(self):
        return f"{self.user}"
