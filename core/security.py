from base64 import urlsafe_b64encode
from hashlib import sha256

from cryptography.fernet import Fernet
from django.conf import settings


def get_fernet():
    key = settings.FIELD_ENCRYPTION_KEY.encode()
    if len(key) != 44:
        key = urlsafe_b64encode(sha256(key).digest())
    return Fernet(key)


def encrypt_value(value):
    if not value:
        return ""
    return get_fernet().encrypt(value.encode()).decode()


def decrypt_value(value):
    if not value:
        return ""
    return get_fernet().decrypt(value.encode()).decode()