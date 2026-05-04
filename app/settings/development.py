from .base import *


DEBUG = True
ALLOWED_HOSTS = ["*"]
CSRF_TRUSTED_ORIGINS = []
EMAIL_BACKEND = env_str("EMAIL_BACKEND", default="django.core.mail.backends.console.EmailBackend")