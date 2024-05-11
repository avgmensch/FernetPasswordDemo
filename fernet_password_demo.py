from os import urandom, mkdir
from os.path import exists, dirname, isfile
from base64 import urlsafe_b64encode

# from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

MSG_FOLDER = "./messages/"
SALT_PATH = f"{MSG_FOLDER}salt.bin"
SALT_SIZE = 16


def get_salt(path: str = SALT_PATH, size: int = SALT_SIZE) -> bytes:
    """Generates a new salt or returns an existing salt (if present)."""
    # Return existing salt
    if isfile(path):
        with open(path, "rb") as f:
            return f.read()
    # Create dir for salt
    if not exists(dirname(path)):
        mkdir(dirname(path))
    # Generate new salt
    salt = urandom(size)
    with open(path, "wb") as f:
        f.write(salt)
    return salt


def get_kdf(salt: bytes, iterations: int = 480000) -> PBKDF2HMAC:
    """
    Creates a [PBKDF2](https://cryptography.io/en/42.0.7/hazmat/primitives/\
key-derivation-functions/#pbkdf2)-key derivation function, later used for
    encoding password and salt for Fernet.
    """
    return PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )


if __name__ == "__main__":
    passwd = b"password"
    salt = get_salt()
    kdf = get_kdf(salt)
    key = urlsafe_b64encode(kdf.derive(passwd))
    print(key)
