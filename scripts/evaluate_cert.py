#!/usr/bin/env python3
"""Evaluate Sentry on the CERT Insider Threat Test Dataset (r4.2 by default).

Download (CC BY 4.0, Carnegie Mellon University, doi:10.1184/R1/12841247):
the release archive and ``answers.tar.bz2``. Only the CSVs Sentry reads are
needed; ``http.csv`` (about 14 GB) is skipped. The Accuracy (CERT) workflow
does all of this on GitHub Actions.

    python scripts/evaluate_cert.py --data r4.2 --answers answers --out results/cert

Runs twice, with and without HR departure context derived from the LDAP
snapshots, because that context is hindsight relative to the logs.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from itds.config import Config  # noqa: E402
from itds.evaluation import (  # noqa: E402
    load_cert_identities,
    load_cert_insiders,
    rolling_evaluate,
)
from itds.ingest.sources import import_files  # noqa: E402

FILES = ("logon.csv", "device.csv", "file.csv", "email.csv")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True, help="extracted release directory")
    ap.add_argument("--answers", type=Path, required=True, help="extracted answers directory")
    ap.add_argument("--release", default="4.2")
    ap.add_argument("--window", type=int, default=14)
    ap.add_argument("--train", type=int, default=60)
    ap.add_argument("--out", type=Path, default=Path("results/cert"))
    args = ap.parse_args()

    t0 = time.perf_counter()
    events, report = import_files("cert", [args.data])
    print(f"Loaded {len(events):,} events for {report['actors']} users "
          f"in {time.perf_counter() - t0:.0f}s ({report['forbidden fields removed']} removed)",
          flush=True)
    insiders = load_cert_insiders(args.answers, args.release)
    print(f"{len(insiders)} insiders in the answer key for r{args.release}", flush=True)

    args.out.mkdir(parents=True, exist_ok=True)
    results = {}
    for label, with_hr in (("with_hr_context", True), ("logs_only", False)):
        identities = load_cert_identities(args.data / "LDAP", departure_context=with_hr)
        t1 = time.perf_counter()

        def progress(w, label=label):
            print(f"  [{label}] {w.start:%Y-%m-%d}: queue {len(w.queue):>2}, "
                  f"active insiders {len(w.active_insiders):>2}, caught {len(w.true_positives)}",
                  flush=True)

        res = rolling_evaluate(events, identities, insiders, config=Config(),
                               window_days=args.window, train_days=args.train,
                               progress=progress)
        res["seconds"] = round(time.perf_counter() - t1)
        results[label] = res
        summary = {k: v for k, v in res.items() if k != "window_detail"}
        print(json.dumps({label: summary}, indent=2), flush=True)

    results["dataset"] = {"release": args.release, "events": len(events),
                          "sources": list(FILES), "skipped": ["http.csv"]}
    (args.out / "cert_results.json").write_text(json.dumps(results, indent=2, default=str))
    print(f"Saved {args.out / 'cert_results.json'}")


if __name__ == "__main__":
    main()
