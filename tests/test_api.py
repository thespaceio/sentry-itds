"""API security and workflow: sessions, roles, two-person reveal, audit chain."""

import pytest
from fastapi.testclient import TestClient

from itds.auth import Authenticator
from itds.ingest.generator import SyntheticGenerator
from itds.pipeline import Pipeline

PASSWORD = "correct horse battery"
REASON = "Case review: bulk restricted access during notice period"


@pytest.fixture(scope="module")
def populated(tmp_path_factory):
    from itds.config import Config

    tmp = tmp_path_factory.mktemp("api")
    cfg = Config()
    cfg.data_dir = tmp
    cfg.db_path = tmp / "api.db"
    events, identities, _ = SyntheticGenerator(n_users=30, days=40, seed=3).generate()
    pipeline = Pipeline(cfg)
    store = pipeline.attach_store(cfg.db_path)
    store.upsert_identities(identities.values())
    result = pipeline.run(events, identities)
    assert result["cases"], "fixture needs at least one case"
    auth = Authenticator(store)
    auth.create_user("ana", PASSWORD, "analyst")
    auth.create_user("ana2", PASSWORD, "analyst")
    auth.create_user("lead", PASSWORD, "lead")
    auth.create_user("lead2", PASSWORD, "lead")
    auth.create_user("root", PASSWORD, "admin")
    return cfg, result


@pytest.fixture
def client(populated):
    from itds.api.main import create_app

    cfg, _ = populated
    return TestClient(create_app(cfg))


def login(client, user):
    r = client.post("/api/login", json={"username": user, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return r


def first_case(client):
    cases = client.get("/api/cases").json()
    return cases[0]


def test_everything_needs_a_session(client):
    for path in ("/api/cases", "/api/summary", "/api/audit", "/api/rules", "/api/attack"):
        assert client.get(path).status_code == 401


def test_wrong_password_is_rejected_and_audited(client, populated):
    r = client.post("/api/login", json={"username": "ana", "password": "nope nope nope"})
    assert r.status_code == 401
    login(client, "lead")
    actions = [e["action"] for e in client.get("/api/audit").json()["entries"]]
    assert "login.failed" in actions


def test_session_cookie_is_httponly_and_strict(client):
    r = login(client, "ana")
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie


def test_security_headers_present(client):
    r = client.get("/api/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_form_posts_are_refused(client):
    """A cross-site form cannot send JSON; the API refuses everything else."""
    r = client.post("/api/login", data={"username": "ana", "password": PASSWORD})
    assert r.status_code == 415


def test_analyst_sees_pseudonyms_not_identities(client):
    login(client, "ana")
    cases = client.get("/api/cases").json()
    assert cases
    for c in cases:
        assert "actor_id" not in c
        assert c["pseudonym"].startswith("EMP-")
    detail = client.get(f"/api/cases/{cases[0]['case_id']}").json()
    assert detail["identity"] is None
    assert "actor_id" not in str(detail["detections_by_day"])
    assert detail["attack_detail"]
    assert detail["timeline"]


def test_analyst_cannot_read_audit_or_approve(client):
    login(client, "ana")
    assert client.get("/api/audit").status_code == 403
    assert client.post("/api/reveals/x/approve").status_code == 403


def test_two_person_reveal(populated):
    from itds.api.main import create_app

    cfg, _ = populated
    app = create_app(cfg)
    analyst, lead, other = TestClient(app), TestClient(app), TestClient(app)
    login(analyst, "ana2")
    login(lead, "lead")
    login(other, "ana")
    case = first_case(analyst)

    # Too short a reason is refused.
    r = analyst.post("/api/reveals", json={"case_id": case["case_id"], "reason": "because"})
    assert r.status_code == 422
    rid = analyst.post("/api/reveals",
                       json={"case_id": case["case_id"], "reason": REASON}).json()["request_id"]

    # Still pseudonymous until a lead approves.
    assert analyst.get(f"/api/cases/{case['case_id']}").json()["identity"] is None
    assert lead.post(f"/api/reveals/{rid}/approve").status_code == 200
    # Cannot be decided twice.
    assert lead.post(f"/api/reveals/{rid}/approve").status_code == 409

    ident = analyst.get(f"/api/cases/{case['case_id']}").json()["identity"]
    assert ident and ident["actor_id"]
    assert lead.get(f"/api/cases/{case['case_id']}").json()["identity"]
    # A third person who was not part of the request still sees a pseudonym.
    assert other.get(f"/api/cases/{case['case_id']}").json()["identity"] is None


def test_lead_cannot_approve_own_request(populated):
    from itds.api.main import create_app

    cfg, _ = populated
    lead = TestClient(create_app(cfg))
    login(lead, "lead2")
    case = first_case(lead)
    rid = lead.post("/api/reveals",
                    json={"case_id": case["case_id"], "reason": REASON}).json()["request_id"]
    assert lead.post(f"/api/reveals/{rid}/approve").status_code == 403


def test_feedback_and_suppression_permissions(client):
    login(client, "ana")
    case = first_case(client)
    r = client.post(f"/api/cases/{case['case_id']}/feedback",
                    json={"disposition": "false_positive", "note": "expected", "suppress_days": 30})
    assert r.status_code == 403  # analysts cannot suppress
    r = client.post(f"/api/cases/{case['case_id']}/feedback",
                    json={"disposition": "true_positive", "note": "confirmed"})
    assert r.status_code == 200


def test_closing_needs_lead_and_disposition(client):
    login(client, "ana")
    case = first_case(client)
    assert client.post(f"/api/cases/{case['case_id']}/status",
                       json={"status": "closed", "disposition": "true_positive"}).status_code == 403
    login(client, "lead")
    assert client.post(f"/api/cases/{case['case_id']}/status",
                       json={"status": "closed"}).status_code == 422
    assert client.post(f"/api/cases/{case['case_id']}/status",
                       json={"status": "closed",
                             "disposition": "true_positive"}).status_code == 200
    assert client.post(f"/api/cases/{case['case_id']}/status",
                       json={"status": "open"}).status_code == 200


def test_admin_manages_users_but_cannot_read_cases(client):
    login(client, "root")
    assert client.get("/api/cases").status_code == 403
    r = client.post("/api/users", json={"username": "newbie", "password": "short",
                                        "role": "analyst"})
    assert r.status_code == 422
    r = client.post("/api/users", json={"username": "newbie", "password": PASSWORD,
                                        "role": "analyst"})
    assert r.status_code == 200


def test_audit_chain_detects_tampering(client, populated):
    cfg, _ = populated
    login(client, "lead")
    body = client.get("/api/audit").json()
    assert body["verify"]["ok"]
    from itds.storage import Store

    store = Store(cfg.db_path)
    with store.connect() as conn:
        original = conn.execute("SELECT actor FROM audit_log WHERE seq = 2").fetchone()[0]
        conn.execute("UPDATE audit_log SET actor = 'someone_else' WHERE seq = 2")
    verify = client.get("/api/audit").json()["verify"]
    assert not verify["ok"]
    assert verify["first_bad_seq"] == 2
    with store.connect() as conn:
        conn.execute("UPDATE audit_log SET actor = ? WHERE seq = 2", (original,))
    assert client.get("/api/audit").json()["verify"]["ok"]


def test_rules_and_attack_endpoints(client):
    login(client, "ana")
    rules = client.get("/api/rules").json()["rules"]
    assert len(rules) >= 10
    assert all(r["attack"] for r in rules)
    matrix = client.get("/api/attack").json()
    assert {t["tactic"] for t in matrix} >= {"Exfiltration", "Collection"}
