import os
from pathlib import Path
from datetime import timedelta
import environ

# ===================== BASE DIR =====================
BASE_DIR = Path(__file__).resolve().parent.parent

# ===================== ENV SETUP =====================
env = environ.Env(
    DEBUG=(bool, False),
    SECRET_KEY=(str, "django-insecure-default-key-change-me"),
    ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
    DATABASE_URL=(str, "sqlite:///db.sqlite3"),  # fallback for CI/test
)

# Load .env if exists
env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(env_file)

# ===================== SECURITY =====================
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")
APPEND_SLASH = False

# ===================== APPLICATIONS =====================
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",

    # Third-party
    "rest_framework",
    "rest_framework_simplejwt",
    "corsheaders",
    "whitenoise.runserver_nostatic",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.apple",

    # Local apps
    "authentication",
    'vendor',
    'django.contrib.gis',
    'ai',

    
]

# ===================== MIDDLEWARE =====================
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

# ===================== URLS & WSGI =====================
ROOT_URLCONF = "myproject.urls"
WSGI_APPLICATION = "myproject.wsgi.application"

# ===================== DATABASE =====================
DATABASES = {
    "default": env.db(),
}

# ===================== AUTH =====================
AUTH_USER_MODEL = "authentication.User"
SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# ===================== REST & JWT =====================
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}


SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=365),   # ১ বছর
    "REFRESH_TOKEN_LIFETIME": timedelta(days=365*9),  # ৯ বছর
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": False,
}

# ===================== TEMPLATES =====================
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

# ===================== EMAIL (Safe Default for CI) =====================
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST", default="localhost")
EMAIL_PORT = env.int("EMAIL_PORT", default=1025)
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS", default=False)
EMAIL_HOST_USER = env("EMAIL_HOST_USER", default="")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", default="")
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# ===================== STATIC & MEDIA =====================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ===================== CORS =====================
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://10.10.7.19:3000",
    "http://10.10.7.86:3000",   # এটা যোগ করুন
]

# অথবা আরো সহজে – পুরো লোকাল নেটওয়ার্ককে allow করুন

# ===================== ALLAUTH =====================
ACCOUNT_LOGIN_METHODS = {"email"}                      # নতুন + সঠিক
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]  # নতুন + সঠিক


ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = "optional"

ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_LOGIN_METHODS = {"email": True}

SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_LOGIN_ON_GET = True

# ===================== GOOGLE & APPLE (with safe defaults) =====================
GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID", default="")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET", default="")
GOOGLE_REDIRECT_URI = env(
    "GOOGLE_REDIRECT_URI", 
    default="http://127.0.0.1:8000/api/auth/google/callback/"
)

APPLE_CLIENT_ID = env("APPLE_CLIENT_ID", default="")
APPLE_SECRET = env("APPLE_SECRET", default="")
APPLE_KEY_ID = env("APPLE_KEY_ID", default="")

# ===================== OTHER =====================
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"