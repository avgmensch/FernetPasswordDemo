from os import urandom, mkdir
from os.path import exists, dirname, isfile
from base64 import urlsafe_b64encode
from time import time

from cryptography.fernet import Fernet
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
    # Input parameters
    PASSWORD = b"password"
    MSG_CLEAR_TEXT = b"This is my secret message..."

    # Generate or get salt
    salt = get_salt()

    # Create Fernet No. 1
    kdf1 = get_kdf(salt)
    key1 = urlsafe_b64encode(kdf1.derive(PASSWORD))
    cipher1 = Fernet(key1)

    # Encrypt and save message
    msg_cipher1_enc = cipher1.encrypt(MSG_CLEAR_TEXT)
    with open(f"{MSG_FOLDER}{time()//1}.txt.lock", "wb") as f:
        f.write(msg_cipher1_enc)

    # Create Fernet No. 2
    kdf2 = get_kdf(salt)
    key2 = urlsafe_b64encode(kdf2.derive(PASSWORD))
    cipher2 = Fernet(key2)

    # Decrypt and save message (new Fernet)
    msg_cipher2_dec = cipher2.decrypt(msg_cipher1_enc)
    print(f"Original and decoded message{" dont't " if MSG_CLEAR_TEXT !=
                                         msg_cipher2_dec else " "}match.")
    with open(f"{MSG_FOLDER}{time()//1}.txt", "wb") as f:
        f.write(msg_cipher2_dec)
