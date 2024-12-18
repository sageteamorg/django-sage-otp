from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now

from sage_otp.models import OTP
from datetime import timedelta

@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    """
    Django Admin configuration for the OTP model.
    """

    list_display = (
        "user",
        "token",
        "state",
        "is_expired",
        "reason",
        "created_at",
        "expire_at",
        "last_sent_at",
    )
    list_filter = ("state", "reason", "last_sent_at")
    search_fields = ("user__username", "user__email", "token")
    ordering = ("-last_sent_at",)
    autocomplete_fields = ("user",)
    list_per_page = 30
    list_select_related = ("user",)

    fieldsets = (
        (_("Basic Information"), {
            "fields": (
                "user",
                "token",
                "state",
                "reason",
            ),
        }),
        (_("Tracking"), {
            "fields": (
                "failed_attempts_count",
                "resend_requests_count",
                "last_sent_at",
            ),
        }),
        (_("Timestamps"), {
            "fields": (
                "created_at",
                "modified_at",
            ),
        }),
    )

    readonly_fields = ("created_at", "modified_at", "last_sent_at")

    def has_delete_permission(self, request, obj=None):
        """
        Allow delete permissions only for superusers.
        """
        if request.user.is_superuser:
            return True
        return False

    def get_queryset(self, request):
        """
        Optimize queryset for performance by prefetching related user data.
        """
        return super().get_queryset(request).select_related("user")

    @admin.display(description="State")
    def formatted_state(self, obj):
        """
        Display the state with additional formatting if needed.
        """
        return obj.get_state_display()

    @admin.display(boolean=True, description="Is Expired")
    def is_expired(self, obj):
        """
        Check if the OTP has expired.
        """
        OTP_LIFETIME = 300  # Example: 5 minutes
        return (obj.created_at + timedelta(seconds=OTP_LIFETIME)) < now()

    @admin.display(description="Expires At")
    def expire_at(self, obj):
        """
        Calculate and display the expiration time of the OTP.
        """
        OTP_LIFETIME = 300  # Example: 5 minutes
        return obj.created_at + timedelta(seconds=OTP_LIFETIME)

    @admin.action(description="Expire Active Tokens")
    def expire_active_tokens(self, request, queryset):
        """
        Mark active tokens as expired if they are not consumed and are already expired.
        """
        updated_count = 0
        for otp in queryset:
            if otp.state == "active" and self.is_expired(otp):
                otp.state = "expired"
                otp.save()
                updated_count += 1

        self.message_user(
            request,
            _(
                f"{updated_count} active tokens were marked as expired."
            ),
            level="info",
        )

    actions = ["expire_active_tokens"]
