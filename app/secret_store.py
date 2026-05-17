import os
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from app.crypto_service import CryptoService


class SecretStore:
    def __init__(self) -> None:
        self.storage_path = os.getenv("SECRETS_STORAGE_PATH", "/app/data/secrets.db")
        self.crypto = CryptoService()
        self._ensure_database()

    def _connect(self) -> sqlite3.Connection:
        storage_dir = os.path.dirname(self.storage_path)

        if storage_dir:
            os.makedirs(storage_dir, exist_ok=True)

        connection = sqlite3.connect(self.storage_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _ensure_database(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS secrets (
                    name TEXT PRIMARY KEY,
                    encrypted_value BLOB NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                )
                """
            )
            connection.commit()

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_secret(self, name: str, value: str) -> dict:
        now = self._utc_now()
        encrypted_value = self.crypto.encrypt(value)

        with self._connect() as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO secrets (
                        name,
                        encrypted_value,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, NULL)
                    """,
                    (name, encrypted_value, now),
                )
                connection.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"Secret '{name}' already exists.") from exc

        return {
            "name": name,
            "created_at": now,
            "updated_at": None,
        }

    def list_secrets(self) -> list[dict]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT name, created_at, updated_at
                FROM secrets
                ORDER BY name ASC
                """
            ).fetchall()

        return [
            {
                "name": row["name"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]

    def get_secret_metadata(self, name: str) -> Optional[dict]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT name, created_at, updated_at
                FROM secrets
                WHERE name = ?
                """,
                (name,),
            ).fetchone()

        if row is None:
            return None

        return {
            "name": row["name"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def get_secret_value(self, name: str) -> Optional[str]:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT encrypted_value
                FROM secrets
                WHERE name = ?
                """,
                (name,),
            ).fetchone()

        if row is None:
            return None

        return self.crypto.decrypt(row["encrypted_value"])

    def update_secret(self, name: str, value: str) -> Optional[dict]:
        now = self._utc_now()
        encrypted_value = self.crypto.encrypt(value)

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE secrets
                SET encrypted_value = ?, updated_at = ?
                WHERE name = ?
                """,
                (encrypted_value, now, name),
            )
            connection.commit()

        if cursor.rowcount == 0:
            return None

        return self.get_secret_metadata(name)

    def delete_secret(self, name: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM secrets
                WHERE name = ?
                """,
                (name,),
            )
            connection.commit()

        return cursor.rowcount > 0

    def get_raw_encrypted_value(self, name: str) -> Optional[bytes]:
        """
        Test/helper method used only to verify that DB does not store plaintext.
        Not exposed as public API.
        """
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT encrypted_value
                FROM secrets
                WHERE name = ?
                """,
                (name,),
            ).fetchone()

        if row is None:
            return None

        return row["encrypted_value"]