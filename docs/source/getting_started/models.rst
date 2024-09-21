Models Layer
============

The models layer defines the database models for handling One-Time Password (OTP) operations. These models track the state, reason for generation, and user-specific data. They can also be integrated into Django’s admin interface for easy management.

OTP
---

The `OTP` model represents a One-Time Password (OTP) token that is associated with a user. This model is used to handle OTP generation, validation, and state transitions.

Fields
^^^^^^

- `user`: A ForeignKey to the Django user model representing the owner of the OTP.
- `token`: A 6-8 digit token representing the OTP.
- `failed_attempts_count`: Tracks the number of incorrect OTP submissions.
- `resend_requests_count`: Tracks the number of OTP resend requests made by the user.
- `state`: The current state of the OTP (active, consumed, expired).
- `reason`: The reason for OTP generation (login, password reset, email activation, etc.).
- `last_sent_at`: Timestamp indicating when the OTP was last sent.
- `created_at`: Timestamp when the OTP was generated.
- `updated_at`: Timestamp when the OTP was last updated.

Methods
^^^^^^^

- `is_valid_token(token: str) -> tuple[bool, OTPState]`: Validates the given token. Returns `True` and the current state if the token is valid, otherwise returns `False` and the state.
- `is_consumed() -> bool`: Checks if the OTP has been consumed.
- `is_expired() -> bool`: Checks if the OTP has expired based on its `created_at` timestamp.
- `is_token_limit_exceeds() -> bool`: Checks if the number of failed attempts exceeds the allowed limit.
- `update_state(new_state: OTPState)`: Updates the OTP state after validating the transition.
- `get_time_elapsed() -> int`: Returns the number of seconds remaining before the OTP expires.

