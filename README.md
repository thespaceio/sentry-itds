# Sentry

Insider threat detection that accumulates risk per person instead of firing an
alert per event.

Most behavioural monitoring fails the same way. It detects unusual activity
accurately, discovers that most unusual activity is innocent, floods the queue,
and gets ignored — at which point it is worse than having nothing, because it
costs analyst hours and provides false assurance. Sentry is built around
avoiding that specific failure.

```
python -m itds generate     # build a labelled synthetic dataset
python -m itds run          # detect, score, rank
```

```
Trained on 130,027 events, scored 45,403 from 2026-09-01
144 detections across 11 entities  |  ML model fitted: True
────────────────────────────────────────────────────────────────────────
Case queue — top 3 of 5

  1. EMP-6daea3   risk 100.0  (off_hours, restricted_data)
       Risk 100 from 33 findings across ml, rules, statistical.
       • Departing employee uploading to personal cloud storage:
         personal_cloud_bytes=7.0 GB on 2026-09-11.
       • Sensitive files accessed at night in volume: night_event_count=711,
         restricted_file_count=709.

  2. EMP-bafa50   risk 100.0  (restricted_data)
       • 222 restricted files read — 3.8x the self baseline of 58.2
         (8.9 standard deviations out).
```

---

## What it does

**Five stages.** Collection → normalization → baselining → three detection
engines → risk scoring. Full design rationale in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

**Three baselines per person.** Self (is this odd *for them*), peer (is this odd
*for their role*), global (is this odd *anywhere*). A new joiner with four days
of history is assessed against their department rather than against a baseline
that does not exist yet.

**Three detection engines.** YAML rules for precision, z-scores for cheap
interpretable coverage, and an Isolation Forest for combinations nobody wrote a
rule for. Unsupervised, because labelled insider threat data does not exist.

**Risk, not alerts.** Findings decay with a seven-day half-life, get multiplied
by context (departing employee ×2, privileged account ×1.5), and accumulate per
person. Cases open when accumulated risk crosses a threshold.

**An alert budget.** The queue is capped at what one analyst can genuinely
review in a day. Everything else is tuned so the right cases fit inside it.

**Explanations, enforced.** `Detection.__post_init__` rejects a finding with an
empty explanation. Not a convention — a constructor error.

**Privacy controls that actually run.** Metadata-only collection with forbidden
fields stripped at ingest, pseudonymous triage, dual-approval break-glass
re-identification, an append-only reveal audit, and enforced retention. See
[docs/PRIVACY.md](docs/PRIVACY.md).

## Install

```bash
git clone https://github.com/th3spaceio/sentry-itds
cd sentry-itds
pip install -r requirements.txt
```

Python 3.11+. Or `docker compose up`.

## Use

```bash
python -m itds generate --users 60 --days 60   # labelled synthetic dataset
python -m itds run --limit 10                  # detect and rank
python -m itds cases                           # the open queue
python -m itds explain u044 --evidence         # every finding for one entity
python -m itds purge                           # apply retention policy
```

Analyst dashboard at `http://localhost:8000`:

```bash
uvicorn itds.api.main:app --reload
```

Re-identifying someone requires a reason and a second approver:

```bash
python -m itds reveal EMP-6daea3 \
  --requested-by analyst1 \
  --approved-by soc-lead \
  --reason "Case 4417: bulk restricted access during notice period"
```

## Current benchmark

On the default synthetic dataset — 60 users, 60 days, ~175k events, five
planted scenarios:

| Metric | Value |
|---|---|
| Recall at alert budget | **1.00** — all three real threats surfaced |
| Precision at alert budget | **0.60** |
| Queue positions of the real threats | **#1, #2, #3** |
| Cases opened | 5 of a 20-case budget |

The two "false positives" are the deliberately planted *negligent* users — high
volume, external sharing, no malice. They rank 4th and 5th, below every real
threat, which is the behaviour the benchmark is designed to test. Catching an
obvious exfiltrator is easy; not burying them under the loudest innocent person
in the company is the actual problem.

**These are synthetic numbers and should be read as such.** They demonstrate
that the ranking logic works on data designed to break it, not that the system
would perform this way on your network. Run it against
[CERT r4.2](docs/DATASET.md) before believing anything about real performance.

Accuracy is deliberately not reported. If 0.1% of users are threats, flagging
nobody scores 99.9% and detects nothing.

## Design decisions worth arguing with

**Repetition is not corroboration.** Tripping the same detection fourteen days
running is one behaviour seen fourteen times, not fourteen findings. Repeats
decay steeply — the second instance is worth a third of the first. Without
this, the noisiest benign user in the organization wins the queue every time.
This single choice moved the real threats from ranks 1/2/5 to 1/2/3.

**Diversity is corroboration.** Flagged by rules *and* statistics *and* the
model earns ×1.25, because the three engines fail in different ways.

**Training and scoring are separated by time.** Baselines are fitted strictly
on data before the scoring window. Skip this and a user's anomalous fortnight
gets absorbed into the definition of their normal — the system stops detecting
anything while continuing to look completely healthy.

**Statistical confidence is capped at 0.9.** An outlier is evidence, never
proof.

**Minimum counts and absolute floors, both.** A user who normally touches two
files and today touched twelve gives an enormous z-score against a near-zero
baseline; that is arithmetic. A user with a genuinely huge baseline can move
gigabytes without shifting their z-score at all; that needs a fixed ceiling.

## Known limitations

- **Synthetic validation only.** Not yet run against CERT or real telemetry.
- **Data classification is path heuristics.** Real deployments should feed
  labels from a DLP or classification system; see `classify_sensitivity`.
- **Peer groups come from department strings.** Clustering on actual behaviour
  would group people better than the org chart does.
- **Attribution is leave-one-out perturbation, not true Shapley values.** Close
  enough to rank drivers, cheap enough to run per case. Install `shap` and swap
  the method if you need exactness.
- **The API has no authentication.** Deliberate for a one-command demo, and
  covered in the pre-deployment checklist in
  [docs/PRIVACY.md](docs/PRIVACY.md).
- **No streaming.** Batch scoring on a schedule. Real-time detection is a
  different architecture, not a configuration change.

## Repository layout

```
itds/
  schema.py            normalized event and identity model
  config.py            every tunable, in one place
  privacy.py           pseudonymization, reveal gate, collection policy
  storage.py           SQLite persistence
  pipeline.py          orchestration
  cli.py               command-line interface
  ingest/              synthetic generator, CSV/JSONL/CERT loaders
  normalize/           schema mapping and identity resolution
  baseline/            self, peer and global profiles; feature extraction
  detect/              rules, statistical, ML engines
  scoring/             risk accumulation, cases, evaluation
  api/                 FastAPI service
  dashboard/           analyst triage interface
rules/                 10 YAML detections
docs/                  architecture, privacy, datasets, rule authoring
tests/                 69 tests
```

## Development

```bash
pip install -r requirements-dev.txt
make test      # 69 tests
make lint
make demo
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — why each layer exists and what breaks without it
- [Privacy and governance](docs/PRIVACY.md) — controls, NDPA 2023, DPIA outline, employee notice
- [Datasets](docs/DATASET.md) — synthetic scenarios, CERT, bringing your own
- [Writing rules](docs/DETECTION_RULES.md) — YAML reference and guidance

## Licence

MIT. See [LICENSE](LICENSE).
