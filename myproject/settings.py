import os
from pathlib import Path
from datetime import timedelta
import environ
import dj_database_url

# ------------------------------
# Base directory
# ------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent

# ------------------------------
# Load environment variables
# ------------------------------
env = environ.Env(
    DEBUG=(bool, False),  # Type casting for DEBUG
    ALLOWED_HOSTS=(list, ["*"]),  # Type casting for ALLOWED_HOSTS
    EMAIL_PORT=(int, 587),  # Type casting for EMAIL_PORT
    EMAIL_USE_TLS=(bool, True)  # Type casting for EMAIL_USE_TLS
)
env_file = os.path.join(BASE_DIR, ".env")
print(f"Looking for .env file at: {env_file}")  # Debug
if os.path.exists(env_file):
    print(f".env file found. Contents:\n{open(env_file).read()}")  # Debug
    environ.Env.read_env(env_file)  # Correct: Use class method
else:
    raise Exception(f".env file not found at {env_file}")

SECRET_KEY = env("SECRET_KEY")
print(f"SECRET_KEY loaded: {SECRET_KEY}")  # Debug
DEBUG = env.bool("DEBUG", default=False)
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS", default=["*"])
GOOGLE_API_KEY = env("GOOGLE_API_KEY")

# ------------------------------
# Installed apps
# ------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "authentication",
    "payment",
    "tts_app",
]

# ------------------------------
# Middleware
# ------------------------------
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # Static files
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# ------------------------------
# URLs & WSGI
# ------------------------------
ROOT_URLCONF = "myproject.urls"
WSGI_APPLICATION = "myproject.wsgi.application"
AUTH_USER_MODEL = "authentication.User"

# ------------------------------
# Templates
# ------------------------------
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ------------------------------
# Database
# ------------------------------
DATABASES = {
    "default": dj_database_url.config(
        default=env("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}"),
        conn_max_age=600,
    )
}

# ------------------------------
# REST Framework
# ------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
}

# ------------------------------
# JWT Settings
# ------------------------------
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# ------------------------------
# Email configuration
# ------------------------------
EMAIL_BACKEND = env("EMAIL_BACKEND")
EMAIL_HOST = env("EMAIL_HOST")
EMAIL_PORT = env.int("EMAIL_PORT")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS")
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")

# ------------------------------
# Static & Media
# ------------------------------
STATIC_URL = "/static/"
STATIC_ROOT = str(BASE_DIR / "staticfiles")
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ------------------------------
# Localization
# ------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"