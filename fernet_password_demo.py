from os import urandom, mkdir
from os.path import exists, dirname, isfile

# from cryptography.fernet import Fernet
# from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from cryptography.hazmat.primitives.hashes import SHA256

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


if __name__ == "__main__":
    salt = get_salt()
    print(salt)
