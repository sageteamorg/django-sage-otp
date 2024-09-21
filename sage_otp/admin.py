"""Django admin configuration for the account.auth.OTP model."""

from django.contrib import admin

from sage_otp.models import OTP


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    """OTP ADMIN."""

    list_display = (
        "user",
        "token",
        "state",
        "reason",
    )
    autocomplete_fields = ("user",)
    list_per_page = 30
    list_select_related = ("user",)
