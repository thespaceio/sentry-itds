"""The feedback loop, alerting and ATT&CK validation."""

import json
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from itds.alerts import Notifier
from itds.audit import AuditLog
from itds.detect.attack import CATALOGUE, FEATURE_TECHNIQUES
from itds.detect.base import Detection
from itds.detect.rules import Rule, load_rules
from itds.feedback import FeedbackStore
from itds.ingest.generator import SyntheticGenerator
from itds.pipeline import Pipeline
from itds.scoring.risk import RiskScorer
from itds.storage import Store

NOW = datetime(2026, 6, 30, tzinfo=UTC)


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    from itds.config import Config

    tmp = tmp_path_factory.mktemp("fb")
    cfg = Config()
    cfg.data_dir, cfg.db_path = tmp, tmp / "fb.db"
    data = SyntheticGenerator(n_users=30, days=40, seed=11).generate()
    pipeline = Pipeline(cfg)
    pipeline.attach_store(cfg.db_path)
    result = pipeline.run(data[0], data[1])
    return cfg, data, result


def test_suppression_removes_detections_on_the_next_run(run):
    cfg, (events, identities, _), first = run
    store = Store(cfg.db_path)
    case = first["cases"][0]
    fb = FeedbackStore(store)
    out = fb.record(case.case_id, "false_positive", "lead1", "known project", suppress_days=30)
    assert out["suppressed"]

    pipeline = Pipeline(cfg)
    pipeline.attach_store(cfg.db_path)
    second = pipeline.run(events, identities)
    assert second["suppressed_detections"] > 0
    names = {d.name for d in second["detections_by_actor"].get(case.actor_id, [])}
    assert not names & set(out["suppressed"])


def test_suppressions_expire(tmp_path):
    fb = FeedbackStore(Store(tmp_path / "s.db"))
    fb.add_suppression("u1", "x", "test", "lead", days=1)
    assert fb.suppression_set() == {("u1", "x")}
    assert fb.suppression_set(datetime.now(UTC) + timedelta(days=2)) == set()
    with pytest.raises(ValueError):
        fb.add_suppression("u1", "x", "forever", "lead", days=3650)


def test_rerun_keeps_the_analysts_decision(run):
    cfg, (events, identities, _), first = run
    store = Store(cfg.db_path)
    case_id = first["cases"][-1].case_id
    store.set_case_status(case_id, "closed", "benign_positive")
    pipeline = Pipeline(cfg)
    pipeline.attach_store(cfg.db_path)
    pipeline.run(events, identities)
    row = store.get_case(case_id)
    assert row["status"] == "closed"
    assert row["disposition"] == "benign_positive"


def test_learned_weights_are_bounded(tmp_path):
    store = Store(tmp_path / "w.db")
    fb = FeedbackStore(store)
    with store.connect() as conn:
        for i in range(6):
            conn.execute("INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?)",
                         (f"f{i}", "c", "u", "false_positive", "a", None,
                          json.dumps(["noisy_rule"]), NOW.isoformat()))
            conn.execute("INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?)",
                         (f"g{i}", "c", "u", "true_positive", "a", None,
                          json.dumps(["good_rule"]), NOW.isoformat()))
    weights = fb.learned_weights()
    assert weights["noisy_rule"] == 0.5
    assert weights["good_rule"] == 1.5
    assert fb.detection_stats()["noisy_rule"]["needs_tuning"]

    det = Detection(actor_id="u", day=NOW.date(), engine="rules", name="noisy_rule",
                    severity="high", explanation="x")
    plain, _ = RiskScorer().score_entity("u", [det], as_of=NOW)
    damped, _ = RiskScorer(learned_weights=weights).score_entity("u", [det], as_of=NOW)
    assert 0 < damped < plain


def test_audit_chain_verifies_and_breaks(tmp_path):
    store = Store(tmp_path / "a.db")
    log = AuditLog(store)
    for i in range(5):
        log.record("lead1", "case.view", f"C-{i}")
    assert log.verify().ok and log.verify().entries == 5
    with store.connect() as conn:
        conn.execute("DELETE FROM audit_log WHERE seq = 3")
    result = log.verify()
    assert not result.ok and result.first_bad_seq == 4


class _Capture(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Capture.received.append(json.loads(body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


def test_webhook_alerts_carry_no_identity(run):
    _, _, result = run
    server = HTTPServer(("127.0.0.1", 0), _Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/hook"
        status = Notifier(webhook_url=url).notify(result["cases"][:2])
        assert status["webhook"].startswith("sent")
    finally:
        server.shutdown()
    payload = json.dumps(_Capture.received)
    assert len(_Capture.received) == min(2, len(result["cases"]))
    assert "EMP-" in payload
    for case in result["cases"][:2]:
        assert case.actor_id not in payload
    _, identities = run[1][0], run[1][1]
    for ident in identities.values():
        assert ident.display_name not in payload


def test_broken_webhook_never_breaks_the_run(run):
    _, _, result = run
    status = Notifier(webhook_url="http://127.0.0.1:9/nothing").notify(result["cases"][:1])
    assert status["webhook"].startswith("failed")


def test_every_rule_maps_to_known_attack_techniques():
    for rule in load_rules("rules"):
        assert rule.attack, f"{rule.id} has no ATT&CK mapping"
        assert all(t in CATALOGUE for t in rule.attack)
    for techs in FEATURE_TECHNIQUES.values():
        assert all(t in CATALOGUE for t in techs)


def test_unknown_attack_id_is_rejected(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "id: bad\ntitle: Bad\nseverity: low\nmatch: {action: x}\nattack: [T9999]\n")
    with pytest.raises(ValueError, match="ATT&CK"):
        load_rules(tmp_path)


def test_rule_with_unknown_context_is_rejected():
    with pytest.raises(ValueError, match="unknown context"):
        Rule(id="r", title="t", severity="low", match={"action": "x"},
             require_context=["vibes"])
