"""File loaders.

Readers only: they yield raw dictionaries. Mapping to ``Event`` and stripping
forbidden fields is the normalizer's job, so every source goes through the same
privacy gate.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator
from pathlib import Path

# http.csv (about 14 GB in r4.2) is opt-in: pass files=CERT_FILES + ("http.csv",).
CERT_FILES = ("logon.csv", "device.csv", "file.csv", "email.csv")


def load_jsonl(path: str | Path) -> Iterator[dict]:
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON ({exc.msg})") from exc


def load_csv(path: str | Path) -> Iterator[dict]:
    with open(path, encoding="utf-8", newline="") as fh:
        yield from csv.DictReader(fh)


def load_cert(directory: str | Path, *, files: tuple[str, ...] = CERT_FILES,
              users: set[str] | None = None) -> Iterator[dict]:
    """Yield rows from a CERT Insider Threat release directory.

    Each row is tagged with ``_cert_source`` so the normalizer knows how to map
    it. ``users`` restricts output to a subset (CERT r4.2 is 32 million rows).
    """
    directory = Path(directory)
    wanted = {u.lower() for u in users} if users else None
    for name in files:
        path = directory / name
        if not path.exists():
            continue
        with open(path, encoding="utf-8", errors="replace", newline="") as fh:
            for row in csv.DictReader(fh):
                if wanted is not None:
                    user = (row.get("user") or "").split("/")[-1].lower()
                    if user not in wanted:
                        continue
                row["_cert_source"] = name
                yield row
