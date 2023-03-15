import os
import base64
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging


class SecretError(Exception):
    pass


class SecretExists(SecretError):
    pass


class BadPassword(SecretError):
    pass


class FileSecrets(object):
    def _get_salt(self) -> bytes:
        salt_path = os.path.join(self.secret_dir, "salt")
        if os.path.exists(salt_path):
            with open(salt_path, "rb") as file:
                self._logger.debug("Reusing existing salt")
                return file.read()

        else:
            salt = os.urandom(32)
            with open(salt_path, "wb") as file:
                file.write(salt)
            self._logger.debug("Generated new Salt")
            return salt

    def __init__(self, secret_dir: str, password: str):
        self._logger = logging.getLogger(__name__)
        self._logger.debug("Starting initialization of FileSecrets")
        self.secret_dir = secret_dir
        os.makedirs(secret_dir, exist_ok=True)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._get_salt(),
            iterations=720000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))
        self.crypto = Fernet(key)
        self._logger.debug("Finished initialization")

    def get_secret(self, secret_name: str) -> str | None:
        """
        Returns the secret at the name or None if it is not found

        Will raise a BadPassword exception if we are unable to decrypt the specified secret file
        """
        secret_path = os.path.join(self.secret_dir, secret_name + ".sec")
        if os.path.exists(secret_path):
            with open(secret_path, "rb") as pw_file:
                encoded_secret = pw_file.read()
                try:
                    decoded_secret = self.crypto.decrypt(encoded_secret)
                except cryptography.fernet.InvalidToken:
                    self._logger.warning("Invalid Password provided to secret engine.")
                    raise BadPassword("Invalid Password provided to secret engine.")
                self._logger.debug(f"Returning secret {secret_name} from {secret_path}")
                return decoded_secret.decode("utf-8")
        else:
            return None

    def set_secret(
        self, secret_name: str, secret_value: str, overwrite: bool = False
    ) -> None:
        """
        Sets the secret of the specified name to the specified value.

        Will raise an SecretExists Exception if the file is already present.
        """
        secret_path = os.path.join(self.secret_dir, secret_name + ".sec")
        if os.path.exists(secret_path) and overwrite == False:
            self._logger.warning(
                f"Cant create secret {secret_name} as it already exists"
            )
            raise SecretExists(f"Cant create secret {secret_name} as it already exists")
        encoded_secret = self.crypto.encrypt(secret_value.encode("utf-8"))
        with open(secret_path, "wb") as pw_file:
            pw_file.write(encoded_secret)
