# settings.py  ← পুরো ফাইলটা এমন করো

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
    DATABASE_URL=(str, "postgresql://user:pass@localhost:5432/dbname"),
)

# .env ফাইল লোড করা (যদি থাকে)
environ.Env.read_env(os.path.join(BASE_DIR, ".env"))

# ===================== SECURITY =====================
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")

# ===================== APPLICATIONS =====================
INSTALLED_APPS = [
    # Django core
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
    "whitenoise.runserver_nostatic",   # production এ Whitenoise
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.apple",

    # Local apps
    "authentication",
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
    "default": env.db(),   # dj-database-url + python-decouple/environ
}

# ===================== AUTH =====================
AUTH_USER_MODEL = "authentication.User"
SITE_ID = 1

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]

# ===================== REST FRAMEWORK & JWT =====================
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=30),
    "AUTH_HEADER_TYPES": ("Bearer",),
}

# ===================== TEMPLATES (এটা ছিল না → এটাই মূল এরর ছিল) =====================
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],          # যদি templates ফোল্ডার থাকে
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",   # allauth + admin এর জন্য জরুরি
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ===================== EMAIL =====================
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST")
EMAIL_PORT = env.int("EMAIL_PORT")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS")
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# ===================== STATIC & MEDIA =====================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ===================== CORS =====================
CORS_ALLOW_ALL_ORIGINS = True   # Development only

# ===================== SOCIAL AUTH (Google + Apple) =====================
SOCIALACCOUNT_PROVIDERS = {
    "google": {
        "APP": {
            "client_id": env("GOOGLE_CLIENT_ID"),
            "secret": env("GOOGLE_CLIENT_SECRET"),
            "key": "",
        },
        "SCOPE": ["profile", "email"],
        "AUTH_PARAMS": {"access_type": "online"},
    },
    "apple": {
        "APP": {
            "client_id": env("APPLE_CLIENT_ID"),
            "secret": env("APPLE_SECRET"),
            "key": env("APPLE_KEY_ID", default=""),
        },
        "SCOPE": ["name", "email"],
    },
}
# ===================== CORS SETTINGS – ফাইনাল + ১০০% কাজ করবে =====================
CORS_ALLOW_ALL_ORIGINS = False          # ← এটা বন্ধ করো (অবশ্যই!)
CORS_ALLOW_CREDENTIALS = True           # ← এটা চালু করো (জরুরি!)

CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",      # React
    "http://127.0.0.1:3000",
    "http://localhost:5000",      # Flutter Web
    "http://10.10.7.19:3000",     # তোমার লোকাল IP থেকে React চালালে
]

# ===================== allauth SETTINGS (আধুনিক + warning-free) =====================
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = False
ACCOUNT_AUTHENTICATION_METHOD = "email"           # এটা এখনো কাজ করে
ACCOUNT_UNIQUE_EMAIL = True
ACCOUNT_EMAIL_VERIFICATION = "optional"

# নতুন ভার্সনে warning বন্ধ করার জন্য
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
ACCOUNT_LOGIN_METHODS = {"email": True}

SOCIALACCOUNT_EMAIL_REQUIRED = True
SOCIALACCOUNT_QUERY_EMAIL = True
SOCIALACCOUNT_LOGIN_ON_GET = True

# ===================== OTHER =====================
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Google OAuth Settings (অবশ্যই যোগ করো!)
GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = env("GOOGLE_REDIRECT_URI", default="http://127.0.0.1:8000/api/auth/google/callback/")