"""Command-line interface.

    python -m itds generate --users 60 --days 60
    python -m itds run
    python -m itds evaluate
    python -m itds cases --limit 10
    python -m itds explain <actor_or_pseudonym>
    python -m itds purge

Deliberately argparse rather than a CLI framework. One less dependency, and
the whole interface fits on a screen.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta

from .config import Config
from .ingest.generator import SyntheticGenerator
from .ingest.loaders import load_jsonl
from .pipeline import Pipeline
from .privacy import RevealDenied, expired_before
from .schema import Event, Identity
from .storage import Store

BAR = "─" * 72


def _load_generated(config: Config):
    events_path = config.data_dir / "events.jsonl"
    identities_path = config.data_dir / "identities.json"
    labels_path = config.data_dir / "labels.json"

    if not events_path.exists():
        print(
            "No dataset found. Run `python -m itds generate` first.", file=sys.stderr
        )
        raise SystemExit(1)

    events = [Event.from_dict(r) for r in load_jsonl(events_path)]
    identities = {}
    if identities_path.exists():
        raw = json.loads(identities_path.read_text())
        for actor_id, d in raw.items():
            identities[actor_id] = Identity(
                actor_id=actor_id,
                display_name=d.get("display_name"),
                department=d.get("department"),
                role=d.get("role"),
                is_privileged=d.get("is_privileged", False),
                joined_on=_dt(d.get("joined_on")),
                departure_notice_on=_dt(d.get("departure_notice_on")),
                last_day_on=_dt(d.get("last_day_on")),
            )
    labels = json.loads(labels_path.read_text()) if labels_path.exists() else {}
    return events, identities, labels


def _dt(value):
    return datetime.fromisoformat(value) if value else None


# -- commands -----------------------------------------------------------


def cmd_generate(args, config: Config) -> None:
    gen = SyntheticGenerator(n_users=args.users, days=args.days, seed=args.seed)
    events, identities, labels = gen.generate()

    config.data_dir.mkdir(parents=True, exist_ok=True)
    with open(config.data_dir / "events.jsonl", "w", encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e.to_dict()) + "\n")

    ident_out = {
        a: {
            "display_name": i.display_name,
            "department": i.department,
            "role": i.role,
            "is_privileged": i.is_privileged,
            "joined_on": i.joined_on.isoformat() if i.joined_on else None,
            "departure_notice_on": i.departure_notice_on.isoformat()
            if i.departure_notice_on
            else None,
            "last_day_on": i.last_day_on.isoformat() if i.last_day_on else None,
        }
        for a, i in identities.items()
    }
    (config.data_dir / "identities.json").write_text(json.dumps(ident_out, indent=2))
    (config.data_dir / "labels.json").write_text(json.dumps(labels, indent=2))

    print(f"{len(events):,} events for {len(identities)} users over {args.days} days")
    print(f"Planted scenarios: {json.dumps(labels, indent=2)}")
    print(f"Written to {config.data_dir}")


def cmd_run(args, config: Config) -> None:
    events, identities, labels = _load_generated(config)
    pipeline = Pipeline(config)
    pipeline.attach_store()

    store = pipeline.store
    store.insert_events(events) if args.persist_events else None
    store.upsert_identities(identities.values())

    last = max(e.timestamp for e in events)
    score_from = last - timedelta(days=args.window)
    result = pipeline.run(events, identities, score_from=score_from)

    print(BAR)
    print(
        f"Trained on {result['events_trained']:,} events, "
        f"scored {result['events_scored']:,} from {result['scored_from'][:10]}"
    )
    print(
        f"{result['total_detections']} detections across "
        f"{result['entities_with_detections']} entities  |  "
        f"ML model fitted: {result['ml_fitted']}"
    )
    if result["insufficient_history"]:
        print(
            f"{len(result['insufficient_history'])} entities skipped "
            "(insufficient history)"
        )
    print(BAR)
    _print_cases(result["cases"], labels, limit=args.limit)

    if labels:
        metrics = pipeline.evaluate(result, labels)
        print(BAR)
        print("Evaluation at alert budget")
        for k in ("precision_at_budget", "recall_at_budget", "f1_at_budget"):
            print(f"  {k:<24} {metrics[k]}")
        print(f"  {'threats found':<24} {metrics['threats_found']}/{metrics['threats_planted']}")
        if metrics["threat_ranks"]:
            print("  queue position of each planted threat:")
            for actor, rank in sorted(metrics["threat_ranks"].items(), key=lambda kv: kv[1]):
                print(f"    #{rank:<3} {actor}  ({labels.get(actor)})")


def cmd_cases(args, config: Config) -> None:
    store = Store(config.db_path)
    rows = store.open_cases(limit=args.limit)
    if not rows:
        print("No open cases. Run `python -m itds run` first.")
        return
    for i, row in enumerate(rows, start=1):
        print(f"{i:>3}. {row['pseudonym'] or row['actor_id']:<12} "
              f"risk {row['risk_score']:>5.1f}   {row['status']}")
        for line in (row["summary"] or "").splitlines():
            print(f"       {line}")
        print()


def cmd_explain(args, config: Config) -> None:
    store = Store(config.db_path)
    detections = store.detections_for(args.actor)
    if not detections:
        print(f"No detections recorded for {args.actor}.")
        return
    print(f"{len(detections)} detections for {args.actor}")
    print(BAR)
    for d in detections:
        print(f"[{d['day']}] {d['severity'].upper():<8} {d['engine']:<12} {d['name']}")
        print(f"          {d['explanation']}")
        if args.evidence and d["evidence"]:
            print(f"          evidence: {json.dumps(d['evidence'], indent=10)[:600]}")
        print()


def cmd_reveal(args, config: Config) -> None:
    """Break-glass re-identification. Requires a reason and a second approver."""
    events, identities, _ = _load_generated(config)
    pipeline = Pipeline(config)
    for actor_id in identities:
        pipeline.pseudonymizer.register(actor_id)
    try:
        actor = pipeline.pseudonymizer.reveal(
            args.pseudonym,
            requested_by=args.requested_by,
            reason=args.reason,
            approved_by=args.approved_by,
            case_id=args.case_id,
        )
    except RevealDenied as exc:
        print(f"Reveal denied: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    store = Store(config.db_path)
    for record in pipeline.pseudonymizer.audit_log:
        store.record_reveal(record)
    ident = identities.get(actor)
    print(f"{args.pseudonym} -> {actor}")
    if ident:
        print(f"  {ident.display_name}, {ident.role}, {ident.department}")
    print("  This reveal has been recorded in the audit log.")


def cmd_purge(args, config: Config) -> None:
    store = Store(config.db_path)
    ev_cutoff = expired_before(config.privacy.event_retention_days)
    case_cutoff = expired_before(config.privacy.case_retention_days)
    n_events = store.purge_events_before(ev_cutoff)
    n_cases = store.purge_closed_cases_before(case_cutoff)
    print(f"Purged {n_events:,} events older than {ev_cutoff:%Y-%m-%d}")
    print(f"Purged {n_cases:,} closed cases older than {case_cutoff:%Y-%m-%d}")


def _print_cases(cases, labels, limit: int) -> None:
    if not cases:
        print("No cases above the risk threshold.")
        return
    print(f"Case queue — top {min(limit, len(cases))} of {len(cases)}\n")
    for i, case in enumerate(cases[:limit], start=1):
        tag = f"  [planted: {labels[case.actor_id]}]" if case.actor_id in labels else ""
        ctx = f"  ({', '.join(case.context)})" if case.context else ""
        print(f"{i:>3}. {case.pseudonym or case.actor_id:<12} risk {case.risk_score:>5.1f}{ctx}{tag}")
        for line in case.summary.splitlines():
            print(f"       {line}")
        print()


# -- entry point --------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="itds", description="Insider threat detection")
    sub = p.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="Build a labelled synthetic dataset")
    g.add_argument("--users", type=int, default=60)
    g.add_argument("--days", type=int, default=60)
    g.add_argument("--seed", type=int, default=42)
    g.set_defaults(func=cmd_generate)

    r = sub.add_parser("run", help="Run the detection pipeline")
    r.add_argument("--window", type=int, default=14, help="Days to score")
    r.add_argument("--limit", type=int, default=10)
    r.add_argument("--persist-events", action="store_true")
    r.set_defaults(func=cmd_run)

    c = sub.add_parser("cases", help="Show the open case queue")
    c.add_argument("--limit", type=int, default=20)
    c.set_defaults(func=cmd_cases)

    e = sub.add_parser("explain", help="Show every detection for one entity")
    e.add_argument("actor")
    e.add_argument("--evidence", action="store_true")
    e.set_defaults(func=cmd_explain)

    rv = sub.add_parser("reveal", help="Break-glass re-identification")
    rv.add_argument("pseudonym")
    rv.add_argument("--requested-by", required=True)
    rv.add_argument("--approved-by", required=True)
    rv.add_argument("--reason", required=True)
    rv.add_argument("--case-id")
    rv.set_defaults(func=cmd_reveal)

    pu = sub.add_parser("purge", help="Apply retention policy")
    pu.set_defaults(func=cmd_purge)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    config = Config.from_env()
    args.func(args, config)


if __name__ == "__main__":
    main()
