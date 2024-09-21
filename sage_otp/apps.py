from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class OtpConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "sage_otp"
    label = "sage_otp"
    verbose_name = _("Sage Otp")
