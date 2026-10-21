#!/usr/bin/env python3
"""Build the static dashboard demo for GitHub Pages.

Generates a synthetic organization, runs the real pipeline, asks the real API
for every page the dashboard needs, and writes the answers to
``site/static/demo-data.json`` next to a copy of the dashboard. The page then
runs entirely in the browser: no server, no real data.

    python scripts/build_demo.py --out site
    python -m http.server -d site 8000
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient  # noqa: E402

from itds.api.main import create_app  # noqa: E402
from itds.audit import AuditLog  # noqa: E402
from itds.auth import Authenticator  # noqa: E402
from itds.config import Config  # noqa: E402
from itds.ingest.generator import SyntheticGenerator  # noqa: E402
from itds.pipeline import Pipeline  # noqa: E402

PASSWORD = "demo-password-not-secret"


def build(out: Path, users: int, days: int, seed: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        cfg = Config()
        cfg.data_dir = Path(tmp)
        cfg.db_path = Path(tmp) / "demo.db"

        events, identities, labels = SyntheticGenerator(users, days, seed).generate()
        pipeline = Pipeline(cfg)
        store = pipeline.attach_store(cfg.db_path)
        store.upsert_identities(identities.values())
        result = pipeline.run(events, identities)
        metrics = pipeline.evaluate(result, labels)
        stats = {
            "events_trained": result["events_trained"],
            "events_scored": result["events_scored"],
            "scored_from": result["scored_from"],
            "detections": result["total_detections"],
            "cases": len(result["cases"]),
        }
        store.record_run("demo", stats)

        auth = Authenticator(store)
        auth.create_user("lead.demo", PASSWORD, "lead")
        client = TestClient(create_app(cfg))
        assert client.post("/api/login", json={"username": "lead.demo",
                                               "password": PASSWORD}).status_code == 200

        cases = client.get("/api/cases?status=all").json()
        details = {c["case_id"]: client.get(f"/api/cases/{c['case_id']}").json() for c in cases}
        for d in details.values():
            d.update(notes=[], feedback=[], reveal_requests=[], identity=None)
        summary = client.get("/api/summary").json()
        rules = client.get("/api/rules").json()
        attack = client.get("/api/attack").json()

        # The demo's audit log starts with the detection run only.
        with store.connect() as conn:
            conn.execute("DELETE FROM audit_log")
        AuditLog(store).record("system", "pipeline.run", None, stats)
        audit = client.get("/api/audit").json()
        audit["entries"] = [e for e in audit["entries"] if e["action"] == "pipeline.run"]

        by_pseudo = {c["pseudonym"]: c["case_id"] for c in cases}
        reveal = {}
        case_labels = {}
        for c in result["cases"]:
            ident = identities[c.actor_id]
            reveal[c.case_id] = {"actor_id": c.actor_id, "display_name": ident.display_name,
                                 "department": ident.department, "role": ident.role}
            if c.actor_id in labels:
                case_labels[c.case_id] = labels[c.actor_id]
        assert set(reveal) == set(by_pseudo.values())

    data = {
        "generated_at": datetime.now(UTC).isoformat(),
        "dataset": {"users": users, "days": days, "seed": seed, "events": len(events)},
        "metrics": metrics,
        "users": {"analyst": "analyst.demo", "lead": "lead.demo"},
        "summary": summary,
        "cases": cases,
        "case_detail": details,
        "identities": reveal,
        "labels": case_labels,
        "rules": rules,
        "attack": attack,
        "audit": audit,
    }

    dash = ROOT / "itds" / "dashboard"
    static = out / "static"
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(dash, static, ignore=shutil.ignore_patterns("index.html"))
    html = (dash / "index.html").read_text(encoding="utf-8")
    html = html.replace('content="live"', 'content="demo"')
    html = html.replace("<title>Sentry</title>", "<title>Sentry demo</title>")
    (out / "index.html").write_text(html, encoding="utf-8")
    (static / "demo-data.json").write_text(json.dumps(data, separators=(",", ":")),
                                           encoding="utf-8")
    (out / ".nojekyll").write_text("")
    return data


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "site")
    ap.add_argument("--users", type=int, default=60)
    ap.add_argument("--days", type=int, default=60)
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    data = build(args.out, args.users, args.days, args.seed)
    size = (args.out / "static" / "demo-data.json").stat().st_size
    print(f"Built {args.out} with {len(data['cases'])} cases "
          f"({data['dataset']['events']:,} synthetic events, demo data {size / 1e3:.0f} KB)")


if __name__ == "__main__":
    main()
