from django.dispatch import Signal

# OTP lifecycle signals
otp_created = Signal()  # Args: user, otp, reason
otp_sent = Signal()  # Args: user, otp, reason
otp_validated = Signal()  # Args: user, otp
otp_expired = Signal()  # Args: user, otp
otp_failed = Signal()  # Args: user, otp, failed_attempts_count
otp_locked = Signal()  # Args: user, otp
otp_reset = Signal()  # Args: user, otp
otp_secret_generated = Signal()  # Args: user, secret
