#!/usr/bin/env python3
"""Benchmark Sentry on many synthetic organizations.

One seed is an anecdote. This runs the full pipeline on N independently
generated datasets and reports how often each planted threat is caught, where
it ranks, and how the careless-but-innocent users and clean leavers score.

    python scripts/benchmark.py --seeds 10 --users 60 --days 60
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from itds.config import Config  # noqa: E402
from itds.ingest.generator import SyntheticGenerator  # noqa: E402
from itds.pipeline import Pipeline  # noqa: E402
from itds.scoring.risk import is_threat_label  # noqa: E402


def run_one(seed: int, users: int, days: int) -> dict:
    events, identities, labels = SyntheticGenerator(users, days, seed).generate()
    config = Config()
    pipeline = Pipeline(config)
    result = pipeline.run(events, identities)
    metrics = pipeline.evaluate(result, labels)

    # Score every entity, including those below the case threshold.
    last = max(e.timestamp for e in events)
    scores = {}
    for actor, dets in result["detections_by_actor"].items():
        s, _ = pipeline.scorer.score_entity(actor, dets, identities.get(actor), as_of=last)
        scores[actor] = s
    clean_departers = [a for a, i in identities.items()
                       if i.departure_notice_on is not None and a not in labels]
    ranked = sorted(scores, key=lambda a: -scores[a])
    return {
        "seed": seed,
        "events": len(events),
        "metrics": metrics,
        "label_scores": {labels[a]: scores.get(a, 0.0) for a in labels},
        "label_ranks": {labels[a]: (ranked.index(a) + 1 if a in scores else None) for a in labels},
        "clean_departer_max": max((scores.get(a, 0.0) for a in clean_departers), default=0.0),
        "max_unlabelled_score": max((s for a, s in scores.items() if a not in labels), default=0.0),
        "cases": len(result["cases"]),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, default=10)
    ap.add_argument("--first-seed", type=int, default=1)
    ap.add_argument("--users", type=int, default=60)
    ap.add_argument("--days", type=int, default=60)
    ap.add_argument("--out", type=Path, default=None, help="write JSON results here")
    args = ap.parse_args()

    runs = []
    t0 = time.perf_counter()
    for seed in range(args.first_seed, args.first_seed + args.seeds):
        r = run_one(seed, args.users, args.days)
        runs.append(r)
        m = r["metrics"]
        ranks = ", ".join(f"{k}#{v}" for k, v in sorted(r["label_ranks"].items()))
        print(f"seed {seed:>3}: recall {m['recall_at_budget']:.2f}  precision "
              f"{m['precision_at_budget']:.2f}  cases {r['cases']:>2}  |  {ranks}", flush=True)

    per_label = defaultdict(list)
    per_rank = defaultdict(list)
    for r in runs:
        for k, v in r["label_scores"].items():
            per_label[k].append(v)
        for k, v in r["label_ranks"].items():
            per_rank[k].append(v)

    summary = {
        "datasets": len(runs),
        "users": args.users,
        "days": args.days,
        "mean_events": round(statistics.mean(r["events"] for r in runs)),
        "recall_mean": round(statistics.mean(r["metrics"]["recall_at_budget"] for r in runs), 3),
        "precision_mean": round(statistics.mean(r["metrics"]["precision_at_budget"] for r in runs), 3),
        "all_threats_top3": sum(
            all(v is not None and v <= 3 for k, v in r["label_ranks"].items() if is_threat_label(k))
            for r in runs),
        "cases_mean": round(statistics.mean(r["cases"] for r in runs), 2),
        "clean_departer_cases": sum(r["clean_departer_max"] >= Config().risk.case_threshold for r in runs),
        "per_scenario": {
            k: {
                "score_mean": round(statistics.mean(v), 1),
                "score_min": min(v),
                "score_max": max(v),
                "rank_median": statistics.median([x for x in per_rank[k] if x is not None] or [0]),
                "rank_worst": max((x for x in per_rank[k] if x is not None), default=None),
            }
            for k, v in sorted(per_label.items())
        },
        "max_unlabelled_score": max(r["max_unlabelled_score"] for r in runs),
        "seconds": round(time.perf_counter() - t0, 1),
    }
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"summary": summary, "runs": runs}, indent=2, default=str))


if __name__ == "__main__":
    main()
