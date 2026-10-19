"""Command-line interface.

    python -m itds generate --users 60 --days 60
    python -m itds run
    python -m itds evaluate
    python -m itds cases --limit 10
    python -m itds explain <actor_or_pseudonym>
    python -m itds purge
    python -m itds import --format windows security.json
    python -m itds attack
    python -m itds user add alice --role analyst
    python -m itds audit verify
    python -m itds serve

Deliberately argparse rather than a CLI framework. One less dependency, and
the whole interface fits on a screen.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import uuid
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


def _write_identities(identities, path) -> None:
    out = {
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
    path.write_text(json.dumps(out, indent=2))


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

    _write_identities(identities, config.data_dir / "identities.json")
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

    stats = {
        "events_trained": result["events_trained"],
        "events_scored": result["events_scored"],
        "scored_from": result["scored_from"],
        "detections": result["total_detections"],
        "entities_with_detections": result["entities_with_detections"],
        "cases": len(result["cases"]),
        "new_cases": len(result["new_case_ids"]),
        "suppressed_detections": result["suppressed_detections"],
        "ml_fitted": result["ml_fitted"],
    }
    store.record_run(str(uuid.uuid4()), stats)
    from .audit import AuditLog
    AuditLog(store).record("system", "pipeline.run", None, stats)

    from .alerts import Notifier
    notifier = Notifier.from_env()
    new_cases = [c for c in result["cases"] if c.case_id in set(result["new_case_ids"])]
    alert_status = notifier.notify(new_cases) if not args.no_alerts else {}

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
    if result["suppressed_detections"]:
        print(f"{result['suppressed_detections']} detections suppressed by analyst feedback")
    if result["new_case_ids"]:
        print(f"{len(result['new_case_ids'])} new case(s)", end="")
        print(f"; alerts: {alert_status}" if alert_status else "")
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
    actor = args.actor
    if actor.startswith("EMP-"):
        actor = store.actor_for_pseudonym(actor) or actor
    detections = store.detections_for(actor)
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
    from .audit import AuditLog
    for record in pipeline.pseudonymizer.audit_log:
        store.record_reveal(record)
        AuditLog(store).record(args.requested_by, "reveal.cli", args.case_id,
                               {"pseudonym": args.pseudonym, "approved_by": args.approved_by,
                                "reason": args.reason})
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
        if case.attack:
            print(f"       ATT&CK: {', '.join(case.attack[:6])}")
        print()


def cmd_import(args, config: Config) -> None:
    from .ingest.sources import import_files

    events, report = import_files(args.format, args.paths, identities=args.identities,
                                 cert_users=args.users,
                                 internal_domains=set(args.internal_domain or []))
    if not events:
        print("No events could be mapped. Check --format.", file=sys.stderr)
        raise SystemExit(1)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    out = config.data_dir / "events.jsonl"
    mode = "a" if args.append else "w"
    with open(out, mode, encoding="utf-8") as fh:
        for e in events:
            fh.write(json.dumps(e.to_dict()) + "\n")
    if args.identities:
        from .ingest.sources import load_identities_csv

        identities = load_identities_csv(args.identities)
        _write_identities(identities, config.data_dir / "identities.json")
        print(f"{len(identities)} identities from {args.identities}")
    if not args.append:
        (config.data_dir / "labels.json").unlink(missing_ok=True)
    print(f"{len(events):,} events written to {out}")
    for k, v in report.items():
        print(f"  {k}: {v}")


def cmd_attack(args, config: Config) -> None:
    from .detect.attack import CATALOGUE, FEATURE_TECHNIQUES
    from .detect.rules import load_rules

    rules = load_rules(config.rules_dir)
    by_tactic: dict[str, list] = {}
    for t in CATALOGUE.values():
        by_tactic.setdefault(t.tactic, []).append(t)
    print("ATT&CK coverage (rules / statistical and ML features)")
    print(BAR)
    for tactic, techs in by_tactic.items():
        print(tactic)
        for t in techs:
            rule_ids = [r.id for r in rules if t.id in r.attack]
            feats = [f for f, ts in FEATURE_TECHNIQUES.items() if t.id in ts]
            mark = "x" if rule_ids or feats else " "
            print(f"  [{mark}] {t.id:<10} {t.name}")
            if rule_ids:
                print(f"        rules:    {', '.join(rule_ids)}")
            if feats:
                print(f"        features: {', '.join(feats)}")
    print(BAR)


def cmd_user(args, config: Config) -> None:
    from .audit import AuditLog
    from .auth import Authenticator

    store = Store(config.db_path)
    auth = Authenticator(store)
    if args.action in ("add", "disable") and not args.username:
        print("A username is required.", file=sys.stderr)
        raise SystemExit(2)
    if args.action == "add":
        password = os.environ.get("ITDS_NEW_USER_PASSWORD") or getpass.getpass(
            f"Password for {args.username} (12+ characters): ")
        try:
            user = auth.create_user(args.username, password, args.role)
        except ValueError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            raise SystemExit(2) from exc
        AuditLog(store).record("cli", "user.create", user.username, {"role": user.role})
        print(f"Created {user.username} ({user.role})")
    elif args.action == "list":
        for u in auth.list_users():
            state = "disabled" if u["disabled"] else "active"
            print(f"{u['username']:<20} {u['role']:<8} {state}")
    elif args.action == "disable":
        if not auth.set_disabled(args.username, True):
            print(f"No such user: {args.username}", file=sys.stderr)
            raise SystemExit(2)
        AuditLog(store).record("cli", "user.disable", args.username)
        print(f"Disabled {args.username}")


def cmd_audit(args, config: Config) -> None:
    from .audit import AuditLog

    log = AuditLog(Store(config.db_path))
    if args.action == "verify":
        result = log.verify()
        print(result)
        raise SystemExit(0 if result.ok else 3)
    if args.action == "head":
        print(log.head())
        return
    for e in reversed(log.entries(limit=args.limit)):
        print(f"{e['seq']:>5}  {e['at'][:19]}  {e['actor']:<12} {e['action']:<18} "
              f"{e['target'] or ''}")


def cmd_rules(args, config: Config) -> None:
    from .feedback import FeedbackStore

    stats = FeedbackStore(Store(config.db_path)).detection_stats()
    if not stats:
        print("No analyst feedback recorded yet.")
        return
    print(f"{'detection':<38} {'verdicts':>8} {'precision':>9}  status")
    for name, s in sorted(stats.items(), key=lambda kv: -kv[1]["verdicts"]):
        p = "-" if s["precision"] is None else f"{s['precision']:.2f}"
        flag = "NEEDS TUNING" if s["needs_tuning"] else ""
        print(f"{name:<38} {s['verdicts']:>8} {p:>9}  {flag}")


def cmd_serve(args, config: Config) -> None:
    import uvicorn

    from .auth import Authenticator

    if not Authenticator(Store(config.db_path)).has_users():
        print("No user accounts exist yet. Create one first, e.g.\n"
              "  python -m itds user add lead1 --role lead", file=sys.stderr)
        raise SystemExit(2)
    uvicorn.run("itds.api.main:app", host=args.host, port=args.port, reload=False)


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
    r.add_argument("--no-alerts", action="store_true", help="Do not send alerts")
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

    im = sub.add_parser("import", help="Import logs into the dataset")
    im.add_argument("--format", required=True,
                    choices=["windows", "auditd", "m365", "cert", "jsonl", "csv"])
    im.add_argument("paths", nargs="+")
    im.add_argument("--identities", help="HR CSV: actor_id, display_name, department, ...")
    im.add_argument("--users", nargs="*", help="CERT only: limit to these user ids")
    im.add_argument("--append", action="store_true")
    im.add_argument("--internal-domain", action="append",
                    help="m365: your email domain(s), for external forwarding rules")
    im.set_defaults(func=cmd_import)

    at = sub.add_parser("attack", help="Show MITRE ATT&CK coverage")
    at.set_defaults(func=cmd_attack)

    ru = sub.add_parser("rules", help="Rule health from analyst feedback")
    ru.set_defaults(func=cmd_rules)

    us = sub.add_parser("user", help="Manage dashboard accounts")
    us.add_argument("action", choices=["add", "list", "disable"])
    us.add_argument("username", nargs="?")
    us.add_argument("--role", choices=["analyst", "lead", "admin"], default="analyst")
    us.set_defaults(func=cmd_user)

    au = sub.add_parser("audit", help="Inspect or verify the audit log")
    au.add_argument("action", choices=["verify", "head", "log"])
    au.add_argument("--limit", type=int, default=50)
    au.set_defaults(func=cmd_audit)

    sv = sub.add_parser("serve", help="Start the API and dashboard")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(func=cmd_serve)

    return p


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    config = Config.from_env()
    args.func(args, config)


if __name__ == "__main__":
    main()
