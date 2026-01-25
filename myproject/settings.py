import os
from pathlib import Path
from datetime import timedelta
import environ

# ===================== BASE DIR & ENV SETUP =====================
BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
)

# .env ফাইল রিড করা
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# ===================== CORE SETTINGS =====================
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")


# ===================== CORE SETTINGS =====================
SECRET_KEY = env("SECRET_KEY")
DEBUG = env("DEBUG")
ALLOWED_HOSTS = env.list("ALLOWED_HOSTS")

# ===================== APPLICATIONS =====================
INSTALLED_APPS = [
    'daphne',                    # ASGI এর জন্য সবার উপরে
    'channels',
    
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles", # collectstatic কমান্ডের জন্য এটি জরুরি
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
    
    # Local apps
    "authentication",
    "vendor",
    "django.contrib.gis",         # GeoDjango (GDAL লাইব্রেরি লাগবে)
    "ai",
]



MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",         # সবার উপরে রাখা ভালো
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",    # Security এর ঠিক পরেই
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "myproject.urls"
WSGI_APPLICATION = "myproject.wsgi.application"
ASGI_APPLICATION = "myproject.asgi.application"

# ===================== DATABASE (PostgreSQL) =====================
DATABASES = {
    "default": env.db(),
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


# ===================== AUTH & JWT =====================
AUTH_USER_MODEL = "authentication.User"
SITE_ID = 1

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
}

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=365),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=365*2),
}

# ===================== EMAIL CONFIG =====================
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = env("EMAIL_HOST")
EMAIL_PORT = env.int("EMAIL_PORT")
EMAIL_USE_TLS = env.bool("EMAIL_USE_TLS")
EMAIL_HOST_USER = env("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

# ===================== STATIC FILES =====================
STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# ===================== CORS & SECURITY =====================
CORS_ALLOW_CREDENTIALS = True


# এখানে সরাসরি আপনার আইপি এবং লোকালহোস্ট দেওয়া হলো (নিরাপদ উপায়)
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://3.144.126.69",      # আপনার AWS IP
    "https://3.144.126.69", 
    "http://api.trekbot.ai",    # <--- নতুন যোগ করা হয়েছে
    "https://api.trekbot.ai",    # যদি SSL ব্যবহার করেন
]

CSRF_TRUSTED_ORIGINS = [
    "http://3.144.126.69",
    "https://3.144.126.69",
    "http://127.0.0.1",
    "https://api.trekbot.ai",   # <--- নতুন
    "http://api.trekbot.ai",
]

# ===================== GOOGLE AUTH =====================
SOCIALACCOUNT_LOGIN_ON_GET = True
# ===================== GOOGLE AUTH =====================
SOCIALACCOUNT_LOGIN_ON_GET = True
GOOGLE_CLIENT_ID = env("GOOGLE_CLIENT_ID", default="")
GOOGLE_CLIENT_SECRET = env("GOOGLE_CLIENT_SECRET", default="")
GOOGLE_REDIRECT_URI = env("GOOGLE_REDIRECT_URI", default="http://localhost:8000/api/auth/google/callback/")

# ===================== CHANNELS =====================
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],
        },
    },
}

# ===================== OTHER =====================
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Dhaka"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

#
