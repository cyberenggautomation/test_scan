"""
Single-file security-scanning fixture.

This module intentionally contains insecure patterns. It is test data for a
code scanner, not an example of how to build an application.

Expected candidate findings include:
- SQL injection
- Unsafe eval
- Shell command injection
- Path traversal
- Unsafe pickle deserialization
- Server-side request forgery (SSRF)
- Weak password hashing
- Cross-site scripting (XSS)
- Sensitive data in logs

The contact details below are fictional.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
import pickle
import sqlite3
import subprocess
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


LOG = logging.getLogger("sample_app")
logging.basicConfig(level=logging.INFO)

DATA_DIR = Path("sample_data")
EXPORT_DIR = Path("exports")

SUPPORT_EMAIL = "jane.doe@example.com"
SUPPORT_PHONE = "212-555-0100"


@dataclass
class User:
    user_id: int
    username: str
    email: str
    role: str = "user"


@dataclass
class Order:
    order_id: int
    user_id: int
    item: str
    total_cents: int


def initialize_database(connection: sqlite3.Connection) -> None:
    """Create tables and insert fictional demonstration data."""
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT NOT NULL,
            password_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS orders (
            order_id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            item TEXT NOT NULL,
            total_cents INTEGER NOT NULL
        );
        """
    )

    connection.execute(
        """
        INSERT OR IGNORE INTO users
        (user_id, username, email, role, password_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            1,
            "jane",
            SUPPORT_EMAIL,
            "user",
            hashlib.md5(b"example-password").hexdigest(),
        ),
    )

    connection.execute(
        """
        INSERT OR IGNORE INTO orders
        (order_id, user_id, item, total_cents)
        VALUES (?, ?, ?, ?)
        """,
        (101, 1, "Notebook", 1299),
    )

    connection.commit()


def find_user_unsafe(
    connection: sqlite3.Connection,
    username: str,
) -> list[tuple[Any, ...]]:
    """Intentional SQL injection: input is interpolated into the query."""
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return connection.execute(query).fetchall()


def find_user_safe(
    connection: sqlite3.Connection,
    username: str,
) -> list[tuple[Any, ...]]:
    """A parameterized version for comparison."""
    return connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,),
    ).fetchall()


def search_orders_unsafe(
    connection: sqlite3.Connection,
    item: str,
    sort_column: str,
) -> list[tuple[Any, ...]]:
    """Two untrusted values are inserted into a SQL statement."""
    query = (
        "SELECT order_id, item, total_cents FROM orders "
        f"WHERE item LIKE '%{item}%' ORDER BY {sort_column}"
    )
    return connection.execute(query).fetchall()


def calculate_unsafe(expression: str) -> Any:
    """Intentional arbitrary-code-execution risk."""
    return eval(expression)


def calculate_safe_sum(numbers: list[float]) -> float:
    """A narrow alternative for a specific calculation."""
    return sum(numbers)


def run_report_unsafe(report_name: str) -> str:
    """Intentional shell injection through shell=True."""
    command = f"echo Generating report: {report_name}"
    result = subprocess.run(
        command,
        shell=True,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_report_safe(report_name: str) -> str:
    """Pass arguments separately and avoid a shell."""
    result = subprocess.run(
        ["echo", "Generating report:", report_name],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def read_document_unsafe(filename: str) -> str:
    """Intentional path traversal: filename may contain '../'."""
    path = DATA_DIR / filename
    return path.read_text(encoding="utf-8")


def read_document_safe(filename: str) -> str:
    """Keep the resolved document inside DATA_DIR."""
    root = DATA_DIR.resolve()
    candidate = (root / filename).resolve()

    if not candidate.is_relative_to(root):
        raise ValueError("Document path is outside the data directory")

    return candidate.read_text(encoding="utf-8")


def export_text_unsafe(filename: str, content: str) -> Path:
    """Another path traversal: a caller controls the output path."""
    target = EXPORT_DIR / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def restore_session_unsafe(serialized_session: bytes) -> Any:
    """Intentional unsafe deserialization of caller-supplied bytes."""
    return pickle.loads(serialized_session)


def restore_preferences_json(data: str) -> dict[str, Any]:
    """A JSON-based comparison with basic type checking."""
    value = json.loads(data)
    if not isinstance(value, dict):
        raise ValueError("Preferences must be a JSON object")
    return value


def fetch_url_unsafe(url: str) -> str:
    """Intentional SSRF risk: the caller controls the destination."""
    with urllib.request.urlopen(url, timeout=5) as response:
        return response.read(4096).decode("utf-8", errors="replace")


def hash_password_weak(password: str) -> str:
    """Intentional weak password storage: fast, unsalted MD5."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def render_profile_unsafe(display_name: str, biography: str) -> str:
    """Intentional XSS risk if this HTML is served to a browser."""
    return (
        "<article>"
        f"<h1>{display_name}</h1>"
        f"<p>{biography}</p>"
        "</article>"
    )


def render_profile_escaped(display_name: str, biography: str) -> str:
    """Escape dynamic values before adding them to HTML."""
    return (
        "<article>"
        f"<h1>{html.escape(display_name)}</h1>"
        f"<p>{html.escape(biography)}</p>"
        "</article>"
    )


def authenticate_unsafe(
    connection: sqlite3.Connection,
    username: str,
    password: str,
) -> bool:
    """Uses the deliberately weak password hash above."""
    rows = connection.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,),
    ).fetchall()

    if not rows:
        return False

    attempted_hash = hash_password_weak(password)
    return attempted_hash == rows[0][0]


def log_support_request_unsafe(
    requester_email: str,
    message: str,
) -> None:
    """Intentional privacy issue: logs an email and full message."""
    LOG.info(
        "Support request from %s: %s",
        requester_email,
        message,
    )


def build_user_response(user: User) -> str:
    """Serialize a user without exposing a password hash."""
    return json.dumps(asdict(user), sort_keys=True)


def summarize_orders(orders: list[Order]) -> dict[str, int]:
    """Ordinary business logic to provide some benign scan content."""
    totals: dict[str, int] = {}

    for order in orders:
        totals[order.item] = totals.get(order.item, 0) + order.total_cents

    return totals


def format_currency(cents: int) -> str:
    if cents < 0:
        raise ValueError("Amount cannot be negative")

    dollars, remainder = divmod(cents, 100)
    return f"${dollars}.{remainder:02d}"


def normalize_username(username: str) -> str:
    return username.strip().lower().replace(" ", "_")


def sample_contact_record() -> dict[str, str]:
    """Fictional PII for testing local PII detection and redaction."""
    return {
        "name": "Jane Doe",
        "email": SUPPORT_EMAIL,
        "phone": SUPPORT_PHONE,
        "note": "Please contact Jane about the demonstration order.",
    }


def main() -> None:
    """Run only benign examples; do not invoke the unsafe input functions."""
    connection = sqlite3.connect(":memory:")

    try:
        initialize_database(connection)

        user = User(
            user_id=1,
            username="jane",
            email=SUPPORT_EMAIL,
        )

        orders = [
            Order(101, 1, "Notebook", 1299),
            Order(102, 1, "Pen", 250),
        ]

        print(build_user_response(user))
        print("Order totals:", summarize_orders(orders))
        print("Sample price:", format_currency(1299))
        print("Normalized username:", normalize_username(" Jane Doe "))

    finally:
        connection.close()


if __name__ == "__main__":
    main()
