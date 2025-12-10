# authentication/apps.py
from django.apps import AppConfig


class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authentication'

    def ready(self):
        # এই লাইনটা অবশ্যই থাকতে হবে — সিগন্যাল লোড করবে
        import authentication.signals  # noqa: F401