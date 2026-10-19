"""Authentication and roles for the API and dashboard.

Three roles, least privilege first:

* ``analyst`` triages pseudonymous cases, writes notes and feedback, and can
  *request* a re-identification.
* ``lead`` does everything an analyst can, approves or denies other people's
  re-identification requests, closes cases, manages suppressions and reads the
  audit log.
* ``admin`` manages accounts. Deliberately not a superset of ``lead``: the
  person who creates accounts should not also be able to approve reveals.

Passwords are hashed with scrypt (standard library). Sessions are random
256-bit tokens; only their SHA-256 is stored, so a stolen database does not
contain usable sessions. Five failed logins lock an account for 15 minutes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

ROLES = ("analyst", "lead", "admin")
PERMISSIONS: dict[str, set[str]] = {
    "analyst": {"cases:read", "cases:feedback", "cases:note", "reveal:request"},
    "lead": {"cases:read", "cases:feedback", "cases:note", "reveal:request",
             "reveal:approve", "cases:close", "suppressions:manage", "audit:read"},
    "admin": {"users:manage", "audit:read"},
}
SESSION_HOURS = 8
MAX_FAILED = 5
LOCKOUT_MINUTES = 15
MIN_PASSWORD_LENGTH = 12

_SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}


class AuthError(Exception):
    """Login failed. The message is safe to show the user."""


@dataclass(frozen=True)
class User:
    username: str
    role: str

    def can(self, permission: str) -> bool:
        return permission in PERMISSIONS.get(self.role, set())


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    salt = base64.b64decode(salt_b64)
    expected = base64.b64decode(digest_b64)
    actual = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return hmac.compare_digest(actual, expected)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(UTC)


# A real scrypt hash of a random password: verifying against it when the user
# does not exist keeps response time the same, so usernames cannot be probed.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


class Authenticator:
    def __init__(self, store) -> None:
        self.store = store

    # -- accounts

    def create_user(self, username: str, password: str, role: str) -> User:
        if role not in ROLES:
            raise ValueError(f"role must be one of {ROLES}")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ValueError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
        username = username.strip().lower()
        if not username.replace(".", "").replace("_", "").replace("-", "").isalnum():
            raise ValueError("username may contain letters, digits, '.', '_' and '-'")
        with self.store.connect() as conn:
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise ValueError(f"user {username!r} already exists")
            conn.execute(
                "INSERT INTO users (username, role, password_hash, created_at) VALUES (?,?,?,?)",
                (username, role, hash_password(password), _now().isoformat()),
            )
        return User(username, role)

    def set_disabled(self, username: str, disabled: bool) -> bool:
        with self.store.connect() as conn:
            cur = conn.execute("UPDATE users SET disabled = ? WHERE username = ?",
                               (int(disabled), username))
            if disabled:
                conn.execute("DELETE FROM sessions WHERE username = ?", (username,))
            return cur.rowcount == 1

    def list_users(self) -> list[dict]:
        with self.store.connect() as conn:
            rows = conn.execute(
                "SELECT username, role, created_at, disabled, locked_until FROM users "
                "ORDER BY username").fetchall()
        return [dict(r) for r in rows]

    def has_users(self) -> bool:
        with self.store.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0

    # -- login and sessions

    def login(self, username: str, password: str) -> tuple[User, str]:
        username = (username or "").strip().lower()
        with self.store.connect() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row is None:
            verify_password(password or "", _DUMMY_HASH)
            raise AuthError("Invalid username or password.")
        if row["disabled"]:
            raise AuthError("This account is disabled.")
        locked_until = row["locked_until"]
        if locked_until and datetime.fromisoformat(locked_until) > _now():
            raise AuthError("Too many failed attempts. Try again later.")

        if not verify_password(password or "", row["password_hash"]):
            failed = row["failed_logins"] + 1
            lock = None
            if failed >= MAX_FAILED:
                lock = (_now() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                failed = 0
            with self.store.connect() as conn:
                conn.execute("UPDATE users SET failed_logins = ?, locked_until = ? "
                             "WHERE username = ?", (failed, lock, username))
            raise AuthError("Invalid username or password.")

        token = secrets.token_urlsafe(32)
        with self.store.connect() as conn:
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL "
                         "WHERE username = ?", (username,))
            conn.execute("DELETE FROM sessions WHERE expires_at < ?", (_now().isoformat(),))
            conn.execute(
                "INSERT INTO sessions (token_hash, username, created_at, expires_at) "
                "VALUES (?,?,?,?)",
                (_token_hash(token), username, _now().isoformat(),
                 (_now() + timedelta(hours=SESSION_HOURS)).isoformat()),
            )
        return User(username, row["role"]), token

    def user_for_token(self, token: str | None) -> User | None:
        if not token:
            return None
        with self.store.connect() as conn:
            row = conn.execute(
                "SELECT u.username, u.role, u.disabled, s.expires_at FROM sessions s "
                "JOIN users u ON u.username = s.username WHERE s.token_hash = ?",
                (_token_hash(token),),
            ).fetchone()
        if row is None or row["disabled"]:
            return None
        if datetime.fromisoformat(row["expires_at"]) < _now():
            return None
        return User(row["username"], row["role"])

    def logout(self, token: str | None) -> None:
        if token:
            with self.store.connect() as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
