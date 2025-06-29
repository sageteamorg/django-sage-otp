"""
Choices for Django.

This module contains Choices classes, which is a subclass of
Django's `TextChoices`. It is used to provide a selection of choices for
field in models.
"""

from django.db import models
from django.utils.translation import gettext_lazy as _

from sage_otp.helpers.exceptions import InvalidStateException


class ReasonOptions(models.TextChoices):
    """
    Reason Options Enumeration for Authentication.

    This class provides five choices:
    'email_activation', 'login', 'reset_password', 'forget_password'
    and 'phone_number_activation'.

    Attributes:
        EMAIL_ACTIVATION (str): The string representing
            the 'email_activation' reason option.
        LOGIN (str): The string representing the 'login' reason option.
        RESET_PASSWORD (str): The string representing
            the 'reset_password' reason option.
        FORGET_PASSWORD (str): The string representing
            the 'forget_password' reason option.
        PHONE_NUMBER_ACTIVATION (str): The string representing the
            'phone_number_activation' reason option.
    """

    EMAIL_ACTIVATION = ("email_activation", _("Email Activation"))
    LOGIN = ("login", _("Login"))
    RESET_PASSWORD = ("reset_password", _("Reset Password"))
    FORGET_PASSWORD = ("forget_password", _("Forget Password"))
    PHONE_NUMBER_ACTIVATION = ("phone_number_activation", _("Phone Number Activation"))


class OTPState(models.TextChoices):
    """
    State Choices Enumeration for Authentication.

    This class provides four choices:
    'Active', 'Consumed', 'Expired', and 'Locked'.

    Attributes:
        ACTIVE (str): The string representing the 'Active' state choice.
        CONSUMED (str): The string representing the 'Consumed' state choice.
        EXPIRED (str): The string representing the 'Expired' state choice.
        LOCKED (str): The string representing the 'Locked' state choice.
    """

    ACTIVE = ("Active", _("Active"))
    CONSUMED = ("Consumed", _("Consumed"))
    EXPIRED = ("Expired", _("Expired"))
    LOCKED = ("Locked", _("Locked"))

    @staticmethod
    def validate_transition(current_state, target_state):
        """
        Validates if a transition from current_state to target_state is allowed.
        
        Valid state transitions:
        - ACTIVE -> CONSUMED, EXPIRED, LOCKED
        - LOCKED -> ACTIVE, EXPIRED
        - CONSUMED -> (no transitions allowed)
        - EXPIRED -> (no transitions allowed)
        """
        valid_choices = [choice[0] for choice in OTPState.choices]
        if current_state not in valid_choices or target_state not in valid_choices:
            raise InvalidStateException(
                f"Invalid state. Valid states are: {', '.join(valid_choices)}. "
                f"Current state: {current_state}, Target state: {target_state}."
            )

        # Define valid state transitions
        valid_transitions = {
            OTPState.ACTIVE: [OTPState.CONSUMED, OTPState.EXPIRED, OTPState.LOCKED],
            OTPState.LOCKED: [OTPState.ACTIVE, OTPState.EXPIRED],  # Allow unlock and expiry
            OTPState.CONSUMED: [],  # Terminal state
            OTPState.EXPIRED: [],   # Terminal state
        }

        allowed_transitions = valid_transitions.get(current_state, [])
        if target_state not in allowed_transitions:
            raise InvalidStateException(
                f"Invalid transition from '{current_state}' to '{target_state}'. "
                f"Allowed transitions: {allowed_transitions}"
            )

    @staticmethod
    def to_consumed(current_state):
        """Transition to CONSUMED state with validation."""
        OTPState.validate_transition(current_state, OTPState.CONSUMED)
        return OTPState.CONSUMED

    @staticmethod
    def to_expired(current_state):
        """Transition to EXPIRED state with validation."""
        OTPState.validate_transition(current_state, OTPState.EXPIRED)
        return OTPState.EXPIRED

    @staticmethod
    def to_active(current_state):
        """Transition to ACTIVE state with validation."""
        OTPState.validate_transition(current_state, OTPState.ACTIVE)
        return OTPState.ACTIVE

    @staticmethod
    def to_locked(current_state):
        """Transition to LOCKED state with validation."""
        OTPState.validate_transition(current_state, OTPState.LOCKED)
        return OTPState.LOCKED

    @classmethod
    def get_terminal_states(cls):
        """Return states that cannot transition to other states."""
        return [cls.CONSUMED, cls.EXPIRED]

    @classmethod
    def get_active_states(cls):
        """Return states that are considered active/usable."""
        return [cls.ACTIVE]

    @classmethod
    def get_inactive_states(cls):
        """Return states that are considered inactive/unusable."""
        return [cls.CONSUMED, cls.EXPIRED, cls.LOCKED]
