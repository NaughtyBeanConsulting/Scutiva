import os
from pathlib import Path

from dotenv import load_dotenv


SETTINGS_DIR = Path(__file__).resolve().parent
APP_DIR = SETTINGS_DIR.parent
BASE_DIR = APP_DIR.parent

load_dotenv(BASE_DIR / ".env")


def env_str(name, default=None, *, required=False):
    value = os.getenv(name, default)
    if required and (value is None or str(value).strip() == ""):
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def env_bool(name, default=False):
    raw_value = env_str(name, str(default))
    return str(raw_value).strip().lower() not in {"0", "false", "no", "off", ""}


def env_int(name, default=0):
    return int(str(env_str(name, default)).strip())


def env_list(name, default=None):
    raw_value = env_str(name, "")
    values = [item.strip() for item in str(raw_value).split(",") if item.strip()]
    return values if values else list(default or [])


def build_allowed_hosts(*, allow_wildcard=False):
    configured_hosts = env_list("ALLOWED_HOSTS", default=["127.0.0.1", "localhost"])
    if "*" in configured_hosts:
        return ["*"]

    hosts = list(configured_hosts)
    for host in ["localhost", "127.0.0.1", "0.0.0.0"]:
        if host not in hosts:
            hosts.append(host)

    if allow_wildcard and "*" not in hosts:
        hosts.append("*")

    return hosts


def build_csrf_trusted_origins(hosts):
    configured_origins = env_list("CSRF_TRUSTED_ORIGINS")
    if configured_origins:
        return configured_origins

    origins = []
    for host in hosts:
        normalized = host.strip()
        if not normalized or normalized == "*":
            continue
        if normalized.startswith("."):
            origins.append(f"https://*{normalized}")
            origins.append(f"https://{normalized[1:]}")
            continue
        if normalized not in {"localhost", "127.0.0.1", "0.0.0.0"}:
            origins.append(f"https://{normalized}")
        origins.append(f"http://{normalized}")
    return list(dict.fromkeys(origins))


SECRET_KEY = env_str("SECRET_KEY", required=True)
DEBUG = env_bool("DEBUG", False)
ALLOWED_HOSTS = build_allowed_hosts()
CSRF_TRUSTED_ORIGINS = build_csrf_trusted_origins(ALLOWED_HOSTS)

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "accounts",
    "dashboard",
    "servers",
    "scanners",
    "vulnerabilities",
    "sboms",
    "reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.app_context",
            ],
        },
    },
]

WSGI_APPLICATION = "app.wsgi.application"
ASGI_APPLICATION = "app.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": env_str("DB_NAME", required=True),
        "USER": env_str("DB_USER", required=True),
        "PASSWORD": env_str("DB_PASSWORD", required=True),
        "HOST": env_str("DB_HOST", required=True),
        "PORT": env_str("DB_PORT", required=True),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard:index"
LOGOUT_REDIRECT_URL = "login"

EMAIL_BACKEND = env_str("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")

SCAN_QUEUE_POLL_SECONDS = env_int("SCAN_QUEUE_POLL_SECONDS", 5)

FIELD_ENCRYPTION_KEY = env_str("FIELD_ENCRYPTION_KEY", required=True)