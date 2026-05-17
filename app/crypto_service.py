import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken


class CryptoService:
    def __init__(self) -> None:
        raw_key = os.getenv("SECRETS_ENCRYPTION_KEY", "").strip()

        if not raw_key:
            raise RuntimeError("SECRETS_ENCRYPTION_KEY is not configured.")

        self._fernet = Fernet(self._normalize_key(raw_key))

    def _normalize_key(self, raw_key: str) -> bytes:
        """
        Fernet requires a urlsafe base64-encoded 32-byte key.

        brdeploy can generate a normal random secret string.
        To keep the deployment flow simple, we derive a valid Fernet key
        from that string using SHA-256.
        """
        digest = hashlib.sha256(raw_key.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(digest)

    def encrypt(self, value: str) -> bytes:
        return self._fernet.encrypt(value.encode("utf-8"))

    def decrypt(self, encrypted_value: bytes) -> str:
        try:
            return self._fernet.decrypt(encrypted_value).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Could not decrypt secret. Encryption key may be invalid.") from exc