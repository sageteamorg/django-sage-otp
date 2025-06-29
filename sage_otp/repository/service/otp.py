"""
This module provides a comprehensive OTP service for handling One-Time Password operations
with improved security, atomic operations, and proper error handling.
"""

import logging
from datetime import timedelta
from typing import Dict, Optional, Tuple, Union, NoReturn

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction, models
from django.db.models import F, Q
from django.utils import timezone

from sage_otp.helpers.choices import OTPState, ReasonOptions
from sage_otp.helpers.exceptions import (
    OTPDoesNotExists,
    OTPExpiredException,
    UserLockedException,
    RateLimitExceededException,
    InvalidTokenException,
    OTPConfigurationException,
)
from sage_otp.signals.otp import (
    otp_created,
    otp_expired,
    otp_failed,
    otp_locked,
    otp_reset,
    otp_secret_generated,
    otp_sent,
    otp_validated
)
from sage_otp.utils.generate import generate_totp, generate_secure_secret

logger = logging.getLogger(__name__)
User = get_user_model()

# Configuration
OTP_LIFETIME = getattr(settings, "OTP_LIFETIME", 300)
OTP_MAX_FAILED_ATTEMPTS = getattr(settings, "OTP_MAX_FAILED_ATTEMPTS", 5)
OTP_MAX_RESEND_ATTEMPTS = getattr(settings, "OTP_MAX_RESEND_ATTEMPTS", 10)
OTP_RESEND_WAIT_TIME = getattr(settings, "OTP_RESEND_WAIT_TIME", 60)
OTP_LOCKOUT_TIME = getattr(settings, "OTP_LOCKOUT_TIME", 3600)


class OTPService:
    """
    Comprehensive OTP service with atomic operations and improved security.
    
    This service handles all OTP-related operations including generation,
    validation, and state management with proper concurrency control.
    """

    def __init__(self):
        self.expire_time = timedelta(seconds=OTP_LIFETIME)
        self.lockout_time = timedelta(seconds=OTP_LOCKOUT_TIME)
        self.resend_wait_time = timedelta(seconds=OTP_RESEND_WAIT_TIME)

    def resolve_user_by_identifier(self, identifier: Union[str, int]) -> User:
        """
        Resolve a user by various identifier types (email, phone, username, ID).
        
        Args:
            identifier: User identifier (email, phone, username, or ID)
            
        Returns:
            User: The resolved user instance
            
        Raises:
            OTPDoesNotExists: If user is not found
        """
        identifier = str(identifier).strip()
        
        try:
            # Try by ID first if it's numeric
            if identifier.isdigit():
                return User.objects.get(pk=int(identifier))
            
            # Try by email
            if "@" in identifier:
                return User.objects.get(email__iexact=identifier)
            
            # Try by phone number
            if identifier.startswith("+") or identifier.replace("-", "").replace(" ", "").isdigit():
                # Assuming phone_number field exists
                if hasattr(User, 'phone_number'):
                    return User.objects.get(phone_number=identifier)
            
            # Try by username
            return User.objects.get(username__iexact=identifier)
            
        except User.DoesNotExist:
            logger.warning("User not found for identifier='%s'", identifier)
            raise OTPDoesNotExists(
                message=f"User not found for identifier: {identifier}",
                params={"identifier": identifier}
            )

    def get_or_create_user_secret(self, user: User) -> str:
        """
        Get or create a secure Base32 secret for the user.
        
        Args:
            user: User instance
            
        Returns:
            str: Base32-encoded secret
        """
        # Assuming the User model has an otp_secret field
        if not hasattr(user, 'otp_secret') or not user.otp_secret:
            secret = generate_secure_secret()
            
            # Use atomic update to prevent race conditions
            with transaction.atomic():
                User.objects.filter(pk=user.pk).update(otp_secret=secret)
                user.refresh_from_db()
                
            logger.info("New OTP secret generated for user_id=%s", user.id)
            otp_secret_generated.send(
                sender=self.__class__, 
                user=user, 
                secret=secret
            )
            
        return user.otp_secret

    def cleanup_expired_otps(self, user: User, reason: str) -> int:
        """
        Clean up expired OTPs for a user and reason.
        
        Args:
            user: User instance
            reason: OTP reason
            
        Returns:
            int: Number of OTPs cleaned up
        """
        from sage_otp.models import OTP
        
        expired_cutoff = timezone.now() - self.expire_time
        
        # Use atomic update to mark expired OTPs
        expired_count = OTP.objects.filter(
            user=user,
            reason=reason,
            state=OTPState.ACTIVE,
            created_at__lt=expired_cutoff
        ).update(state=OTPState.EXPIRED)
        
        if expired_count > 0:
            logger.info(
                "Marked %d expired OTPs for user_id=%s, reason=%s", 
                expired_count, user.id, reason
            )
            
        return expired_count

    def unlock_expired_lockouts(self, user: User, reason: str) -> int:
        """
        Unlock OTPs whose lockout time has expired.
        
        Args:
            user: User instance  
            reason: OTP reason
            
        Returns:
            int: Number of OTPs unlocked
        """
        from sage_otp.models import OTP
        
        unlocked_count = OTP.objects.filter(
            user=user,
            reason=reason,
            state=OTPState.LOCKED,
            lockout_end_time__lt=timezone.now()
        ).update(
            state=OTPState.ACTIVE,
            failed_attempts_count=0,
            lockout_end_time=None
        )
        
        if unlocked_count > 0:
            logger.info(
                "Unlocked %d OTPs for user_id=%s, reason=%s", 
                unlocked_count, user.id, reason
            )
            
        return unlocked_count

    @transaction.atomic
    def get_or_create_otp(self, identifier: str, reason: str) -> Tuple['OTP', bool]:
        """
        Get or create an OTP with proper atomic operations.
        
        Args:
            identifier: User identifier
            reason: OTP reason
            
        Returns:
            Tuple[OTP, bool]: (otp_instance, was_created)
        """
        from sage_otp.models import OTP
        
        user = self.resolve_user_by_identifier(identifier)
        
        # Clean up expired OTPs and unlock expired lockouts
        self.cleanup_expired_otps(user, reason)
        self.unlock_expired_lockouts(user, reason)
        
        # Try to get existing active OTP
        try:
            otp = OTP.objects.select_for_update().get(
                user=user,
                reason=reason,
                state=OTPState.ACTIVE
            )
            logger.debug("Using existing OTP. OTP ID=%s, user_id=%s", otp.id, user.id)
            return otp, False
            
        except OTP.DoesNotExist:
            # Create new OTP
            secret = self.get_or_create_user_secret(user)
            token = generate_totp(secret)
            
            otp = OTP.objects.create(
                user=user,
                reason=reason,
                token=token,
                state=OTPState.ACTIVE,
                last_sent_at=timezone.now(),
            )
            
            logger.info("OTP created. OTP ID=%s, user_id=%s", otp.id, user.id)
            otp_created.send(
                sender=self.__class__, 
                user=user, 
                otp=otp, 
                reason=reason
            )
            
            return otp, True

    def check_rate_limits(self, otp: 'OTP') -> Optional[Dict[str, Union[bool, int]]]:
        """
        Check various rate limits for the OTP.
        
        Args:
            otp: OTP instance
            
        Returns:
            Optional[Dict]: Rate limit information if limited, None otherwise
        """
        # Check resend rate limit
        if otp.last_sent_at:
            next_allowed = otp.last_sent_at + self.resend_wait_time
            if timezone.now() < next_allowed:
                remaining = int((next_allowed - timezone.now()).total_seconds())
                return {
                    "rate_limited": True,
                    "reason": "resend_too_soon",
                    "wait_seconds": remaining
                }
        
        # Check maximum resend attempts
        if otp.resend_requests_count >= OTP_MAX_RESEND_ATTEMPTS:
            return {
                "rate_limited": True,
                "reason": "max_resend_attempts",
                "attempts": otp.resend_requests_count
            }
        
        return None

    @transaction.atomic
    def send_otp(self, identifier: str, reason: str) -> Optional[Dict[str, Union[bool, int]]]:
        """
        Send an OTP with proper rate limiting and atomic operations.
        
        Args:
            identifier: User identifier
            reason: OTP reason
            
        Returns:
            Optional[Dict]: Rate limit info if limited, None if sent successfully
        """
        otp, created = self.get_or_create_otp(identifier, reason)
        
        # Check rate limits
        rate_limit_info = self.check_rate_limits(otp)
        if rate_limit_info:
            logger.info(
                "OTP send rate limited. OTP ID=%s, reason=%s", 
                otp.id, rate_limit_info.get("reason")
            )
            return rate_limit_info
        
        # Update OTP atomically
        OTP.objects.filter(pk=otp.pk).update(
            resend_requests_count=F('resend_requests_count') + 1,
            last_sent_at=timezone.now(),
            state=OTPState.ACTIVE
        )
        
        # Refresh from DB to get updated values
        otp.refresh_from_db()
        
        logger.info("OTP sent. OTP ID=%s, user_id=%s", otp.id, otp.user.id)
        otp_sent.send(
            sender=self.__class__, 
            user=otp.user, 
            otp=otp, 
            reason=reason
        )
        
        return None

    @transaction.atomic
    def verify_otp(self, identifier: str, token: str, reason: str) -> Dict[str, bool]:
        """
        Verify an OTP token with atomic operations to prevent race conditions.
        
        Args:
            identifier: User identifier
            token: OTP token to verify
            reason: OTP reason
            
        Returns:
            Dict[str, bool]: Verification result
            
        Raises:
            OTPDoesNotExists: If no active OTP found
            OTPExpiredException: If OTP has expired
            UserLockedException: If user is locked out
        """
        from sage_otp.models import OTP
        
        user = self.resolve_user_by_identifier(identifier)
        
        try:
            # Get OTP with select_for_update to prevent race conditions
            otp = OTP.objects.select_for_update().get(
                user=user,
                reason=reason,
                state=OTPState.ACTIVE
            )
        except OTP.DoesNotExist:
            logger.warning(
                "No active OTP found for user_id=%s, reason=%s", 
                user.id, reason
            )
            raise OTPDoesNotExists(
                message="No active OTP found",
                params={"identifier": identifier, "reason": reason}
            )
        
        # Check if OTP is expired
        if otp.is_expired():
            otp.state = OTPState.EXPIRED
            otp.save(update_fields=['state', 'modified_at'])
            
            logger.warning("OTP expired during verification. OTP ID=%s", otp.id)
            otp_expired.send(sender=self.__class__, user=user, otp=otp)
            
            raise OTPExpiredException("OTP has expired")
        
        # Check if OTP is locked
        if otp.is_locked():
            remaining = otp.get_lockout_remaining_time()
            logger.warning("OTP is locked. OTP ID=%s, remaining=%ds", otp.id, remaining)
            raise UserLockedException(
                f"User is locked for {remaining} more seconds",
                params={"lockout_remaining": remaining}
            )
        
        # Verify token
        if otp.token == token:
            # Success - mark as consumed
            otp.state = OTPState.CONSUMED
            otp.save(update_fields=['state', 'modified_at'])
            
            logger.info("OTP verified successfully. OTP ID=%s", otp.id)
            otp_validated.send(sender=self.__class__, user=user, otp=otp)
            
            return {"verified": True}
        
        else:
            # Failed verification - increment counter atomically
            updated_rows = OTP.objects.filter(pk=otp.pk).update(
                failed_attempts_count=F('failed_attempts_count') + 1
            )
            
            if updated_rows == 0:
                # OTP was modified by another process
                logger.warning("OTP was modified during verification. OTP ID=%s", otp.id)
                raise InvalidTokenException("OTP verification failed due to concurrent modification")
            
            # Refresh to get updated count
            otp.refresh_from_db()
            
            # Check if we need to lock the OTP
            if otp.failed_attempts_count >= OTP_MAX_FAILED_ATTEMPTS:
                lockout_end = timezone.now() + self.lockout_time
                OTP.objects.filter(pk=otp.pk).update(
                    state=OTPState.LOCKED,
                    lockout_end_time=lockout_end
                )
                otp.refresh_from_db()
                
                logger.warning("OTP locked due to max attempts. OTP ID=%s", otp.id)
                otp_locked.send(sender=self.__class__, user=user, otp=otp)
                
                raise UserLockedException(
                    "User locked due to too many failed attempts",
                    params={"failed_attempts": otp.failed_attempts_count}
                )
            
            logger.info(
                "OTP verification failed. OTP ID=%s, attempts=%d", 
                otp.id, otp.failed_attempts_count
            )
            otp_failed.send(
                sender=self.__class__,
                user=user,
                otp=otp,
                failed_attempts_count=otp.failed_attempts_count
            )
            
            return {"verified": False, "attempts_remaining": OTP_MAX_FAILED_ATTEMPTS - otp.failed_attempts_count}

    @transaction.atomic
    def reset_otp(self, identifier: str, reason: str) -> 'OTP':
        """
        Reset an OTP by generating a new token and clearing counters.
        
        Args:
            identifier: User identifier
            reason: OTP reason
            
        Returns:
            OTP: Reset OTP instance
        """
        from sage_otp.models import OTP
        
        user = self.resolve_user_by_identifier(identifier)
        
        try:
            otp = OTP.objects.select_for_update().get(
                user=user,
                reason=reason,
                state__in=[OTPState.ACTIVE, OTPState.LOCKED]
            )
        except OTP.DoesNotExist:
            raise OTPDoesNotExists(
                message="No OTP found to reset",
                params={"identifier": identifier, "reason": reason}
            )
        
        # Generate new token
        secret = self.get_or_create_user_secret(user)
        new_token = generate_totp(secret)
        
        # Reset OTP
        otp.token = new_token
        otp.failed_attempts_count = 0
        otp.resend_requests_count = 0
        otp.lockout_end_time = None
        otp.state = OTPState.ACTIVE
        otp.last_sent_at = timezone.now()
        otp.save()
        
        logger.info("OTP reset. OTP ID=%s, user_id=%s", otp.id, user.id)
        otp_reset.send(sender=self.__class__, user=user, otp=otp)
        
        return otp


# Convenience functions for specific use cases
class OTPServiceFacade:
    """Facade providing convenient methods for common OTP operations."""
    
    def __init__(self):
        self.service = OTPService()
    
    def send_email_activation_otp(self, email: str) -> Optional[Dict[str, Union[bool, int]]]:
        """Send OTP for email activation."""
        return self.service.send_otp(email, ReasonOptions.EMAIL_ACTIVATION)
    
    def send_login_otp(self, identifier: str) -> Optional[Dict[str, Union[bool, int]]]:
        """Send OTP for login."""
        return self.service.send_otp(identifier, ReasonOptions.LOGIN)
    
    def send_password_reset_otp(self, identifier: str) -> Optional[Dict[str, Union[bool, int]]]:
        """Send OTP for password reset."""
        return self.service.send_otp(identifier, ReasonOptions.RESET_PASSWORD)
    
    def send_phone_activation_otp(self, phone: str) -> Optional[Dict[str, Union[bool, int]]]:
        """Send OTP for phone number activation."""
        return self.service.send_otp(phone, ReasonOptions.PHONE_NUMBER_ACTIVATION)
    
    def verify_email_activation_otp(self, email: str, token: str) -> Dict[str, bool]:
        """Verify OTP for email activation."""
        return self.service.verify_otp(email, token, ReasonOptions.EMAIL_ACTIVATION)
    
    def verify_login_otp(self, identifier: str, token: str) -> Dict[str, bool]:
        """Verify OTP for login."""
        return self.service.verify_otp(identifier, token, ReasonOptions.LOGIN)
    
    def verify_password_reset_otp(self, identifier: str, token: str) -> Dict[str, bool]:
        """Verify OTP for password reset."""
        return self.service.verify_otp(identifier, token, ReasonOptions.RESET_PASSWORD)
    
    def verify_phone_activation_otp(self, phone: str, token: str) -> Dict[str, bool]:
        """Verify OTP for phone activation."""
        return self.service.verify_otp(phone, token, ReasonOptions.PHONE_NUMBER_ACTIVATION)
