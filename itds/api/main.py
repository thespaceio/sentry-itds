"""Sentry API and dashboard server.

    uvicorn itds.api.main:app            (or: python -m itds serve)

Every endpoint except login and health needs a session. Analysts see
pseudonyms only; the real identity behind a case appears only after a lead who
is not the requester approves a written reveal request, and only to those two
people. Everything is written to the hash-chained audit log.

Security notes:
* Sessions are HttpOnly, SameSite=Strict cookies, so other sites cannot ride
  them. Set ``ITDS_COOKIE_SECURE=1`` behind HTTPS (always, in production).
* State-changing requests must be JSON. A cross-site HTML form cannot send
  JSON without a CORS preflight, which this server never grants.
* A strict Content-Security-Policy allows scripts and styles from this origin
  only. The dashboard has no inline script and loads nothing from a CDN.
"""

from __future__ import annotations

import os
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..audit import AuditLog
from ..auth import ROLES, Authenticator, AuthError, User
from ..config import Config
from ..detect.attack import CATALOGUE, FEATURE_TECHNIQUES, describe
from ..detect.rules import load_rules
from ..feedback import DISPOSITIONS, FeedbackStore
from ..privacy import Pseudonymizer, RevealDenied
from ..storage import Store

COOKIE = "sentry_session"
DASHBOARD_DIR = Path(__file__).resolve().parent.parent / "dashboard"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
}


# -- request bodies -------------------------------------------------------------

class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class FeedbackBody(BaseModel):
    disposition: Literal["true_positive", "benign_positive", "false_positive"]
    note: str = Field(default="", max_length=2000)
    suppress_days: int | None = Field(default=None, ge=1, le=180)


class NoteBody(BaseModel):
    body: str = Field(min_length=1, max_length=4000)


class StatusBody(BaseModel):
    status: Literal["open", "closed"]
    disposition: Literal["true_positive", "benign_positive", "false_positive"] | None = None


class RevealRequestBody(BaseModel):
    case_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=2000)


class UserBody(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["analyst", "lead", "admin"]


# -- helpers -------------------------------------------------------------------

def _public_case(case: dict) -> dict:
    """A case as an analyst may see it: no real identifier."""
    out = {k: v for k, v in case.items() if k != "actor_id"}
    out["top_detections"] = [
        {k: v for k, v in d.items() if k != "actor_id"} for d in case.get("top_detections", [])
    ]
    return out


def _public_detection(d: dict) -> dict:
    return {k: v for k, v in d.items() if k not in ("actor_id",)}


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config.from_env()
    store = Store(config.db_path)
    auth = Authenticator(store)
    audit = AuditLog(store)
    feedback = FeedbackStore(store)
    secure_cookie = os.environ.get("ITDS_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}

    app = FastAPI(title="Sentry", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.url.path.startswith(
                "/api/"):
            ctype = request.headers.get("content-type", "")
            has_body = request.headers.get("content-length", "0") not in {"0", ""}
            if has_body and not ctype.startswith("application/json"):
                return JSONResponse({"detail": "JSON body required"}, status_code=415,
                                    headers=SECURITY_HEADERS)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    # -- auth dependencies

    def current_user(request: Request) -> User:
        user = auth.user_for_token(request.cookies.get(COOKIE))
        if user is None:
            raise HTTPException(401, "Not signed in")
        return user

    def need(permission: str):
        def dep(user: User = Depends(current_user)) -> User:
            if not user.can(permission):
                raise HTTPException(403, "Your role does not allow this")
            return user
        return dep

    def case_or_404(case_id: str) -> dict:
        case = store.get_case(case_id)
        if case is None:
            raise HTTPException(404, "No such case")
        return case

    # -- public

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.post("/api/login")
    def login(body: LoginBody, request: Request, response: Response):
        client = request.client.host if request.client else None
        try:
            user, token = auth.login(body.username, body.password)
        except AuthError as exc:
            audit.record(body.username.strip().lower()[:64], "login.failed", None,
                         {"ip": client, "reason": str(exc)})
            raise HTTPException(401, str(exc)) from exc
        response.set_cookie(COOKIE, token, httponly=True, samesite="strict",
                            secure=secure_cookie, max_age=8 * 3600, path="/")
        audit.record(user.username, "login.success", None, {"ip": client})
        return {"username": user.username, "role": user.role}

    @app.post("/api/logout")
    def logout(request: Request, response: Response):
        token = request.cookies.get(COOKIE)
        user = auth.user_for_token(token)
        auth.logout(token)
        response.delete_cookie(COOKIE, path="/")
        if user:
            audit.record(user.username, "logout")
        return {"ok": True}

    @app.get("/api/me")
    def me(user: User = Depends(current_user)):
        from ..auth import PERMISSIONS
        return {"username": user.username, "role": user.role,
                "permissions": sorted(PERMISSIONS[user.role])}

    # -- overview

    @app.get("/api/summary")
    def summary(user: User = Depends(need("cases:read"))):
        cases = store.list_cases(limit=1000)
        open_cases = [c for c in cases if c["status"] == "open"]
        tactics: Counter = Counter()
        techniques: Counter = Counter()
        contexts: Counter = Counter()
        engines: Counter = Counter()
        for c in open_cases:
            for t in c["attack"]:
                techniques[t] += 1
                if t in CATALOGUE:
                    tactics[CATALOGUE[t].tactic] += 1
            for ctx in c["context"]:
                contexts[ctx] += 1
            for e in c["engines"]:
                engines[e] += 1
        pending = 0
        with store.connect() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM reveal_requests WHERE status = 'pending'").fetchone()[0]
        return {
            "open_cases": len(open_cases),
            "closed_cases": len(cases) - len(open_cases),
            "alert_budget": config.risk.alert_budget,
            "case_threshold": config.risk.case_threshold,
            "high_risk": sum(1 for c in open_cases if c["risk_score"] >= 85),
            "pending_reveals": pending,
            "tactics": dict(tactics.most_common()),
            "techniques": dict(techniques.most_common()),
            "contexts": dict(contexts.most_common()),
            "engines": dict(engines.most_common()),
            "last_run": store.last_run(),
            "active_suppressions": len(feedback.active_suppressions()),
        }

    # -- cases

    @app.get("/api/cases")
    def list_cases(status: Literal["open", "closed", "all"] = "open",
                   user: User = Depends(need("cases:read"))):
        rows = store.list_cases(None if status == "all" else status)
        return [_public_case(c) for c in rows]

    @app.get("/api/cases/{case_id}")
    def get_case(case_id: str, user: User = Depends(need("cases:read"))):
        case = case_or_404(case_id)
        detections = store.detections_for(case["actor_id"])
        by_day: dict[str, list] = defaultdict(list)
        for d in detections:
            by_day[d["day"]].append(_public_detection(d))
        timeline = store.entity_days(case["actor_id"])
        with store.connect() as conn:
            notes = [dict(r) for r in conn.execute(
                "SELECT * FROM case_notes WHERE case_id = ? ORDER BY at", (case_id,))]
            requests = [dict(r) for r in conn.execute(
                "SELECT * FROM reveal_requests WHERE case_id = ? ORDER BY created_at DESC",
                (case_id,))]

        identity = None
        for req in requests:
            if req["status"] == "approved" and user.username in (
                    req["requested_by"], req["decided_by"]):
                ident = store.load_identities().get(case["actor_id"])
                identity = {
                    "actor_id": case["actor_id"],
                    "display_name": ident.display_name if ident else None,
                    "department": ident.department if ident else None,
                    "role": ident.role if ident else None,
                    "revealed_by_request": req["request_id"],
                }
                break

        audit.record(user.username, "case.view", case_id,
                     {"identity_shown": identity is not None})
        out = _public_case(case)
        out.update({
            "detections_by_day": dict(sorted(by_day.items(), reverse=True)),
            "detection_count": len(detections),
            "timeline": timeline,
            "notes": notes,
            "feedback": feedback.for_case(case_id),
            "reveal_requests": requests,
            "identity": identity,
            "attack_detail": describe(case["attack"]),
        })
        return out

    @app.post("/api/cases/{case_id}/feedback")
    def give_feedback(case_id: str, body: FeedbackBody,
                      user: User = Depends(need("cases:feedback"))):
        case_or_404(case_id)
        suppress = body.suppress_days if body.disposition == "false_positive" else None
        if suppress and not user.can("suppressions:manage"):
            raise HTTPException(403, "Only a lead can suppress detections")
        result = feedback.record(case_id, body.disposition, user.username, body.note,
                                 suppress_days=suppress)
        audit.record(user.username, "case.feedback", case_id,
                     {"disposition": body.disposition, "suppressed": result["suppressed"]})
        return result

    @app.post("/api/cases/{case_id}/notes")
    def add_note(case_id: str, body: NoteBody, user: User = Depends(need("cases:note"))):
        case_or_404(case_id)
        note_id = str(uuid.uuid4())
        with store.connect() as conn:
            conn.execute("INSERT INTO case_notes VALUES (?,?,?,?,?)",
                         (note_id, case_id, user.username, body.body.strip(),
                          datetime.now(UTC).isoformat()))
        audit.record(user.username, "case.note", case_id, {"note_id": note_id})
        return {"note_id": note_id}

    @app.post("/api/cases/{case_id}/status")
    def set_status(case_id: str, body: StatusBody, user: User = Depends(need("cases:close"))):
        case_or_404(case_id)
        if body.status == "closed" and body.disposition is None:
            raise HTTPException(422, "Closing a case needs a disposition")
        store.set_case_status(case_id, body.status, body.disposition)
        audit.record(user.username, f"case.{'close' if body.status == 'closed' else 'reopen'}",
                     case_id, {"disposition": body.disposition})
        return {"ok": True}

    # -- re-identification

    @app.post("/api/reveals")
    def request_reveal(body: RevealRequestBody, user: User = Depends(need("reveal:request"))):
        case = case_or_404(body.case_id)
        reason = body.reason.strip()
        if len(reason) < 15:
            raise HTTPException(422, "The reason must describe the investigation, "
                                     "not just name it (15 characters or more).")
        rid = str(uuid.uuid4())
        with store.connect() as conn:
            conn.execute(
                "INSERT INTO reveal_requests (request_id, pseudonym, case_id, requested_by, "
                "reason, created_at) VALUES (?,?,?,?,?,?)",
                (rid, case["pseudonym"], body.case_id, user.username, reason,
                 datetime.now(UTC).isoformat()))
        audit.record(user.username, "reveal.request", body.case_id,
                     {"request_id": rid, "pseudonym": case["pseudonym"], "reason": reason})
        return {"request_id": rid, "status": "pending"}

    @app.get("/api/reveals")
    def list_reveals(user: User = Depends(need("reveal:request"))):
        with store.connect() as conn:
            if user.can("reveal:approve"):
                rows = conn.execute("SELECT * FROM reveal_requests ORDER BY created_at DESC")
            else:
                rows = conn.execute("SELECT * FROM reveal_requests WHERE requested_by = ? "
                                    "ORDER BY created_at DESC", (user.username,))
            return [dict(r) for r in rows.fetchall()]

    def _decide(request_id: str, user: User, approve: bool):
        with store.connect() as conn:
            req = conn.execute("SELECT * FROM reveal_requests WHERE request_id = ?",
                               (request_id,)).fetchone()
        if req is None:
            raise HTTPException(404, "No such request")
        if req["status"] != "pending":
            raise HTTPException(409, f"Request already {req['status']}")
        if req["requested_by"] == user.username:
            raise HTTPException(403, "You cannot decide your own request")
        if approve:
            actor = store.actor_for_pseudonym(req["pseudonym"])
            if actor is None:
                raise HTTPException(404, "Pseudonym not found")
            pz = Pseudonymizer(config.privacy)
            pz._reverse[req["pseudonym"]] = actor  # reverse map from the case store
            try:
                pz.reveal(req["pseudonym"], requested_by=req["requested_by"],
                          reason=req["reason"], approved_by=user.username,
                          case_id=req["case_id"])
            except RevealDenied as exc:
                raise HTTPException(422, str(exc)) from exc
            for record in pz.audit_log:
                store.record_reveal(record)
        status = "approved" if approve else "denied"
        with store.connect() as conn:
            conn.execute("UPDATE reveal_requests SET status = ?, decided_by = ?, decided_at = ? "
                         "WHERE request_id = ?",
                         (status, user.username, datetime.now(UTC).isoformat(), request_id))
        audit.record(user.username, f"reveal.{'approve' if approve else 'deny'}",
                     req["case_id"], {"request_id": request_id,
                                      "requested_by": req["requested_by"]})
        return {"request_id": request_id, "status": status}

    @app.post("/api/reveals/{request_id}/approve")
    def approve(request_id: str, user: User = Depends(need("reveal:approve"))):
        return _decide(request_id, user, True)

    @app.post("/api/reveals/{request_id}/deny")
    def deny(request_id: str, user: User = Depends(need("reveal:approve"))):
        return _decide(request_id, user, False)

    # -- rules, ATT&CK, feedback health

    @app.get("/api/rules")
    def rules(user: User = Depends(need("cases:read"))):
        stats = feedback.detection_stats()
        out = []
        for r in load_rules(config.rules_dir):
            out.append({
                "id": r.id, "title": r.title, "severity": r.severity,
                "confidence": r.confidence, "description": (r.description or "").strip(),
                "require_context": r.require_context, "tags": r.tags,
                "attack": describe(r.attack), "kind": "match" if r.match else "aggregate",
                "conditions": r.conditions, "health": stats.get(r.id),
            })
        engine_stats = {k: v for k, v in stats.items() if not any(k == r["id"] for r in out)}
        return {"rules": out, "other_detections": engine_stats}

    @app.get("/api/attack")
    def attack(user: User = Depends(need("cases:read"))):
        rules_by_tech: dict[str, list[str]] = defaultdict(list)
        for r in load_rules(config.rules_dir):
            for t in r.attack:
                rules_by_tech[t].append(r.id)
        feats_by_tech: dict[str, list[str]] = defaultdict(list)
        for f, ts in FEATURE_TECHNIQUES.items():
            for t in ts:
                feats_by_tech[t].append(f)
        seen: Counter = Counter()
        for c in store.list_cases("open", limit=1000):
            for t in c["attack"]:
                seen[t] += 1
        by_tactic: dict[str, list] = defaultdict(list)
        for t in CATALOGUE.values():
            by_tactic[t.tactic].append({
                **t.to_dict(), "rules": rules_by_tech.get(t.id, []),
                "features": feats_by_tech.get(t.id, []), "open_cases": seen.get(t.id, 0),
            })
        order = ["Initial Access", "Execution", "Persistence", "Defense Evasion",
                 "Credential Access", "Discovery", "Lateral Movement", "Collection",
                 "Exfiltration"]
        return [{"tactic": k, "techniques": by_tactic[k]} for k in order if k in by_tactic]

    @app.get("/api/suppressions")
    def suppressions(user: User = Depends(need("cases:read"))):
        out = []
        for s in feedback.active_suppressions():
            row = {k: v for k, v in s.items() if k != "actor_id"}
            row["pseudonym"] = Pseudonymizer(config.privacy).pseudonym(s["actor_id"])
            out.append(row)
        return out

    @app.delete("/api/suppressions/{suppression_id}")
    def remove_suppression(suppression_id: str,
                           user: User = Depends(need("suppressions:manage"))):
        if not feedback.remove_suppression(suppression_id):
            raise HTTPException(404, "No such suppression")
        audit.record(user.username, "suppression.remove", suppression_id)
        return {"ok": True}

    # -- audit

    @app.get("/api/audit")
    def audit_entries(limit: int = 200, user: User = Depends(need("audit:read"))):
        return {"entries": audit.entries(min(max(limit, 1), 1000)),
                "verify": audit.verify().__dict__}

    # -- users

    @app.get("/api/users")
    def users(user: User = Depends(need("users:manage"))):
        return auth.list_users()

    @app.post("/api/users")
    def add_user(body: UserBody, user: User = Depends(need("users:manage"))):
        try:
            created = auth.create_user(body.username, body.password, body.role)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        audit.record(user.username, "user.create", created.username, {"role": created.role})
        return {"username": created.username, "role": created.role}

    @app.post("/api/users/{username}/disable")
    def disable_user(username: str, user: User = Depends(need("users:manage"))):
        if username == user.username:
            raise HTTPException(422, "You cannot disable your own account")
        if not auth.set_disabled(username, True):
            raise HTTPException(404, "No such user")
        audit.record(user.username, "user.disable", username)
        return {"ok": True}

    # -- dashboard

    if DASHBOARD_DIR.exists():
        app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(DASHBOARD_DIR / "index.html")

    app.state.store = store
    app.state.auth = auth
    app.state.audit = audit
    app.state.roles = ROLES
    app.state.dispositions = DISPOSITIONS
    return app


def _lazy_app() -> FastAPI:
    return create_app()


class _LazyApp:
    """``uvicorn itds.api.main:app`` builds the app on first use, so importing
    this module (for tests or tooling) does not create a database."""

    _app: FastAPI | None = None

    async def __call__(self, scope, receive, send):
        if self._app is None:
            self._app = _lazy_app()
        await self._app(scope, receive, send)


app = _LazyApp()
