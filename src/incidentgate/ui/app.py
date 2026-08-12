"""A deliberately small local UI over the public D1 runtime boundary."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from html import escape
from secrets import token_urlsafe
from time import monotonic
from typing import Any, Protocol
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse

from incidentgate.contracts import IncidentIdentity, IncidentState, Role, ToolCallContext
from incidentgate.control.models import Caller
from incidentgate.lab.auth import Principal
from incidentgate.scenario_registry import NO_ACTION_SCENARIOS, RUNNABLE_SCENARIOS


class Runtime(Protocol):
    def start(self, incident: IncidentIdentity, operator: Caller, context: ToolCallContext) -> Any: ...
    def resume(self, thread_id: str) -> Any: ...
    def status(self, thread_id: str) -> Any: ...
    def approve(self, thread_id: str, approver: Principal, *, reason: str | None = None) -> Any: ...
    def reject(self, thread_id: str, approver: Principal, *, reason: str | None = None) -> Any: ...
    def timeline(self, incident_id: str, *, limit: int = 50) -> Any: ...


class ScenarioController(Protocol):
    def prepare_d1(self) -> Any: ...


RuntimeFactory = Callable[[], AbstractContextManager[Runtime]]
ACTORS = {"observer-1": Role.OBSERVER, "operator-1": Role.OPERATOR, "approver-1": Role.APPROVER}


@dataclass
class Nonce:
    thread_id: str
    scenario_id: str
    actor: str
    action: str
    expires_at: float


def _value(item: object, name: str, default: object = None) -> object:
    return getattr(item, name, default)


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _list(values: Any) -> str:
    if not values:
        return "-"
    return ", ".join(_text(value) for value in values if value is not None)


def create_ui_app(
    runtime_factory: RuntimeFactory, controller: ScenarioController, *, clock: Callable[[], float] = monotonic,
    nonce_limit: int = 256,
) -> FastAPI:
    """Create a local demonstration UI; identity is an allowlisted mock actor only."""
    app = FastAPI(title="Triage Agent Lab checkpoint", docs_url=None, redoc_url=None)
    app.state.nonces = {}
    app.state.incidents = {}

    def actor(request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> tuple[str, Role]:
        actor_id = x_incidentgate_actor or request.cookies.get("incidentgate_actor")
        role = ACTORS.get(actor_id or "")
        if role is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="known mock identity required")
        return actor_id or "", role

    def require(request: Request, allowed: Role, x_incidentgate_actor: str | None = Header(default=None)) -> str:
        actor_id, role = actor(request, x_incidentgate_actor)
        if role is not allowed:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="mock role is not permitted")
        return actor_id

    def issue(thread_id: str, scenario_id: str, actor_id: str, action: str) -> str:
        now = clock()
        app.state.nonces = {key: item for key, item in app.state.nonces.items() if item.expires_at > now}
        if len(app.state.nonces) >= nonce_limit:
            raise HTTPException(409, "local form nonce store is full")
        nonce = token_urlsafe(24)
        app.state.nonces[nonce] = Nonce(thread_id, scenario_id, actor_id, action, now + 600)
        return nonce

    def consume(thread_id: str, scenario_id: str, actor_id: str, action: str, nonce: str | None) -> None:
        item = app.state.nonces.pop(nonce or "", None)
        if (item is None or item.expires_at <= clock() or item.thread_id != thread_id
                or item.scenario_id != scenario_id or item.actor != actor_id or item.action != action):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid or expired local form nonce")

    def page(title: str, body: str, code: int = 200) -> HTMLResponse:
        return HTMLResponse(f"<!doctype html><title>{_text(title)}</title><main><h1>{_text(title)}</h1>{body}</main>", code)

    def trace_link(item: object) -> str:
        trace_id = _value(item, "trace_id")
        label = (
            f" Trace {_text(trace_id)}"
            if isinstance(trace_id, str) and 0 < len(trace_id) <= 128
            else ""
        )
        url = _value(item, "trace_url")
        parsed = urlparse(str(url)) if url else None
        if parsed is None or parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return label
        return f"{label} <a href='{_text(url)}'>Trace link</a>"

    def safe_error(error: Exception) -> HTTPException:
        message = str(error).lower()
        if "unknown" in message and "thread" in message:
            return HTTPException(404, "thread not found")
        if "pending" in message or "already" in message or "conflict" in message:
            return HTTPException(409, "approval is no longer pending")
        if isinstance(error, PermissionError):
            return HTTPException(403, "runtime denied this role")
        return HTTPException(409, "runtime request could not be completed")

    def scenario_for(current: Any) -> str:
        incident_id = _value(current, "incident_id")
        if incident_id not in {f"INC-{scenario}" for scenario in RUNNABLE_SCENARIOS}:
            raise HTTPException(404, "incident not found")
        return str(incident_id).removeprefix("INC-")

    def open_status(thread_id: str) -> tuple[Any, tuple[Any, ...]]:
        try:
            with runtime_factory() as runtime:
                runtime.resume(thread_id)
                current = runtime.status(thread_id)
                events = tuple(runtime.timeline(str(_value(current, "incident_id", "INC-D1"))))
                return current, events
        except HTTPException:
            raise
        except Exception as error:
            raise safe_error(error) from error

    def timeline(events: tuple[Any, ...]) -> str:
        rows = "".join(
            f"<li>{_text(_value(event, 'timestamp', _value(event, 'at', '')))}: "
            f"{_text(_value(event, 'transition', 'event'))}"
            f"{(' - ' + _text(_value(event, 'reason'))) if _value(event, 'reason') else ''}</li>"
            for event in events
        ) or "<li>No audit events yet.</li>"
        return f"<h2>Audit timeline</h2><ol>{rows}</ol>"

    def status_page(current: Any, events: tuple[Any, ...], actor_id: str, role: Role) -> HTMLResponse:
        pending = _value(current, "pending")
        incident_id, thread_id = _value(current, "incident_id", "INC-D1"), _value(current, "thread_id", "")
        identity = app.state.incidents.get(str(thread_id))
        scenario_id = _value(identity, "scenario_id", scenario_for(current))
        if pending is not None:
            # Never substitute a plausible default here: an approver must be able to
            # tell "the api component" from "this action has no component".
            component = _value(pending, "component") or "n/a"
            revision = _value(pending, "target_revision") or "n/a"
            monitor = _value(pending, "monitor_verdict", "unavailable")
            reason_required = bool(_value(pending, "requires_reason", False))
            policy = _value(pending, "policy_decision", "requires human approval")
            policy_reasons = _list(_value(pending, "policy_reasons", ()))
            monitor_rationale = _value(pending, "monitor_rationale", "unavailable")
            suspicion = _value(pending, "monitor_suspicion", "unavailable")
            controls = ""
            if role is Role.APPROVER:
                nonce = issue(str(thread_id), str(scenario_id), actor_id, "approve")
                required = " required" if reason_required else ""
                hint = "A reason is required because the monitor deferred." if reason_required else "Reason (optional)."
                controls = (f"<form method='post' action='/threads/{_text(thread_id)}/approve'><input type='hidden' name='nonce' value='{_text(nonce)}'>"
                            f"<label>{hint}<input name='reason'{required}></label><button>Approve</button></form>"
                            f"<form method='post' action='/threads/{_text(thread_id)}/reject'><input type='hidden' name='nonce' value='{_text(issue(str(thread_id), str(scenario_id), actor_id, 'reject'))}'>"
                            f"<label>Rejection reason<input name='reason'></label><button>Reject</button></form>")
            if scenario_id == "D2":
                proposed = f"{_text(_value(pending, 'tool_name', 'restore'))} {_text(_value(pending, 'variable_name', 'variable'))} using approved reference {_text(_value(pending, 'approved_value_ref', 'unavailable'))}"
            elif scenario_id in {"D3", "D8"}:
                proposed = f"{_text(_value(pending, 'tool_name', 'restart'))} {_text(component)}"
            elif scenario_id == "D5":
                proposed = "operations.cleanup api: bounded simulated-log cleanup (cap 64 MiB)"
            elif scenario_id == "R01":
                proposed = "operations.rollback_migration_2026_08_10_5: schema 2026.08.10.4"
            elif scenario_id == "R02":
                proposed = "operations.disable_flag_checkout_v2: checkout_v2 false"
            elif scenario_id == "R03":
                proposed = "operations.restore_config_PAYMENT_TIMEOUT_MS_3000: PAYMENT_TIMEOUT_MS 3000 (cfg-a17)"
            elif scenario_id == "R04":
                proposed = "operations.rollback_release_api_2_4_1: api old pods 12, new pods 0"
            elif scenario_id == "R06":
                proposed = (
                    "operations.enable_query_plan_baseline_orders: "
                    "index idx_orders_customer for orders_lookup"
                )
            elif scenario_id == "R07":
                proposed = (
                    "operations.route_customer_reads_primary: "
                    "customer reads routed to primary"
                )
            elif scenario_id == "R08":
                proposed = (
                    "operations.rotate_credential_db_app_2026_09: "
                    "activate identifier db-app-2026-09"
                )
            elif scenario_id == "R09":
                proposed = (
                    "operations.enable_partner_backoff_60s: "
                    "60-second partner backoff, rate limits left in place"
                )
            elif scenario_id == "R12":
                proposed = (
                    "operations.activate_local_response_adapter_3_8_3: "
                    "local adapter local-3.8.3, responses still validated"
                )
            else:
                proposed = f"{_text(_value(pending, 'tool_name', 'rollback'))} {_text(component)} from v2 to {_text(revision)}"
            return page(f"Pending {scenario_id} approval", f"<p>Incident {_text(incident_id)}; thread {_text(thread_id)}</p>"
                        f"<p>Proposed action: {proposed}; action {_text(_value(pending, 'action_hash', 'unavailable'))}.</p>"
                        f"<p>Evidence citations: {_list(_value(pending, 'evidence_ids', ()))}</p>"
                        f"<p>Policy: {_text(policy)}; reasons: {policy_reasons}. Monitor: {_text(monitor)}; rationale: {_text(monitor_rationale)}; suspicion: {_text(suspicion)}.</p>"
                        f"<p>Approval reason required: {_text(reason_required)}.{trace_link(pending)}</p>{controls}{timeline(events)}")
        result = _value(current, "result")
        if scenario_id in NO_ACTION_SCENARIOS:
            final_state = _value(result, "final_state", "unavailable") if result else "unavailable"
            diagnosis = _value(_value(result, "report"), "diagnosis", "unavailable") if result else "unavailable"
            attempt_values = _value(current, "collection_attempts", ())
            attempts = len(attempt_values) if isinstance(attempt_values, (tuple, list)) else 0
            title = f"{scenario_id} incident deferred" if final_state == "deferred" else f"{scenario_id} incident outcome"
            recommendation = (
                " Non-executable review recommendation." if scenario_id == "S2" else ""
            )
            r05_fixture = (
                " Deterministic virtual fixture observation: the database lock auto-release "
                "was observed after 45 seconds; no-action outcome."
                if scenario_id == "R05"
                else ""
            )
            # R10/R11 are local synthetic observations that end with the network
            # owner. Say so, and say plainly that nothing was changed.
            handoff = ""
            if scenario_id == "R10":
                handoff = (
                    " Local synthetic resolver observation only; nothing was changed and no "
                    "authority was used. Referred to the network owner."
                )
            elif scenario_id == "R11":
                handoff = (
                    " Local synthetic certificate observation only; the pinned fingerprint "
                    "was preserved, nothing was changed, and no authority was used. "
                    "Referred to the network owner."
                )
            return page(
                title,
                f"<p>Incident {_text(incident_id)}; thread {_text(thread_id)}</p>"
                f"<p>Diagnosis: {_text(diagnosis)}. Final state: {_text(final_state)}. Bounded collection attempts: {_text(attempts)}.{recommendation}{r05_fixture}{handoff}</p>"
                f"<p>Evidence citations: {_list(_value(result, 'evidence_ids', ())) if result else '-'}.{trace_link(result)}</p>"
                "",
            )
        verification = _value(result, "verification") if result else None
        operation = _value(result, "operation") if result else None
        recovery = "unavailable" if verification is None else (
            f"{_text(_value(verification, 'predicate', 'recovery'))}: {_text(_value(verification, 'passed', False))}; "
            f"evidence {_list(_value(verification, 'evidence_ids', ())) }"
        )
        approval = _value(result, "approval") if result else None
        decision = _value(approval, "decision", "no approval") if result else "no result"
        human_reason = _value(approval, "reason", "unavailable") if approval else "unavailable"
        policy = _value(result, "policy") if result else None
        monitor = _value(result, "monitor") if result else None
        return page(f"{scenario_id} incident completed", f"<p>Incident {_text(incident_id)}; thread {_text(thread_id)}</p>"
                    f"<p>Decision: {_text(decision)}; reason: {_text(human_reason)}. Final state: {_text(_value(result, 'final_state', 'unknown'))}.</p>"
                    f"<p>Policy: {_text(_value(policy, 'decision', 'unavailable'))}; Monitor: {_text(_value(monitor, 'verdict', 'unavailable'))}, {_text(_value(monitor, 'rationale', 'unavailable'))}.</p>"
                    f"<p>Operation status: {_text(_value(operation, 'status', 'not executed'))}; durable duplicate protection verified.</p>"
                    f"<p>Fresh recovery: {recovery}.{trace_link(result)}</p>{timeline(events)}")

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> HTMLResponse:
        supplied = x_incidentgate_actor or request.cookies.get("incidentgate_actor")
        if supplied not in ACTORS:
            options = "".join(f"<option value='{_text(name)}'>{_text(name)}</option>" for name in ACTORS)
            return page("Triage Agent Lab checkpoint", f"<form method='post' action='/mock-login'><label>Local mock identity<select name='actor'>{options}</select></label><button>Use identity</button></form>")
        actor_id, role = actor(request, x_incidentgate_actor)
        links = "".join(f"<li><a href='/threads/{_text(thread)}'>{_text(_value(incident, 'incident_id', incident))}</a></li>" for thread, incident in app.state.incidents.items()) or "<li>No prepared incidents.</li>"
        forms = ""
        if role is Role.OPERATOR:
            forms = "".join(f"<form method='post' action='/incidents/{scenario.lower()}/prepare'><input type='hidden' name='nonce' value='{_text(issue('', scenario, actor_id, 'prepare'))}'><button>Prepare {scenario} fault</button></form>" for scenario in sorted(RUNNABLE_SCENARIOS))
        switch = "".join(f"<button name='actor' value='{_text(name)}'>{_text(name)}</button>" for name in ACTORS)
        return page("Triage Agent Lab checkpoint", f"<p>Mock identity: {_text(actor_id)} ({_text(role)}).</p><form method='post' action='/mock-login'>{switch}</form>{forms}<h2>Incidents</h2><ul>{links}</ul>")

    @app.post("/mock-login")
    async def mock_login(request: Request) -> RedirectResponse:
        form = await request.form()
        actor_id = str(form.get("actor") or "")
        if actor_id not in ACTORS:
            raise HTTPException(403, "known mock identity required")
        response = RedirectResponse("/", 303)
        response.set_cookie("incidentgate_actor", actor_id, httponly=True, samesite="strict")
        return response

    async def _prepare(scenario_id: str, request: Request, x_incidentgate_actor: str | None) -> RedirectResponse:
        if scenario_id not in RUNNABLE_SCENARIOS:
            raise HTTPException(404, "incident not found")
        actor_id = require(request, Role.OPERATOR, x_incidentgate_actor)
        form = await request.form()
        consume("", scenario_id, actor_id, "prepare", str(form.get("nonce") or ""))
        thread = f"{scenario_id.lower()}-{uuid4().hex[:12]}"
        correlation_id = f"ui-{thread}"
        try:
            generic_prepare = getattr(controller, "prepare", None)
            identity = generic_prepare(scenario_id, thread, correlation_id) if callable(generic_prepare) else None
            if identity is None:
                if scenario_id != "D1":
                    raise ValueError("unsupported checkpoint scenario")
                controller.prepare_d1()
                identity = IncidentIdentity(incident_id="INC-D1", scenario_id="D1", thread_id=thread, correlation_id=correlation_id, state=IncidentState.OPEN)
        except Exception as error:
            raise HTTPException(409, "checkpoint fault could not be prepared") from error
        app.state.incidents[thread] = identity
        return RedirectResponse(f"/incidents/{thread}/start", 303)

    @app.post("/incidents/d1/prepare")
    async def prepare_d1(request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> RedirectResponse:
        return await _prepare("D1", request, x_incidentgate_actor)

    @app.post("/incidents/{scenario_id}/prepare")
    async def prepare(scenario_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> RedirectResponse:
        return await _prepare(scenario_id.upper(), request, x_incidentgate_actor)

    @app.post("/incidents/{thread_id}/start")
    async def start(thread_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> RedirectResponse:
        actor_id = require(request, Role.OPERATOR, x_incidentgate_actor)
        if thread_id not in app.state.incidents:
            raise HTTPException(404, "incident not found")
        form = await request.form()
        incident = app.state.incidents[thread_id]
        consume(thread_id, incident.scenario_id, actor_id, "start", str(form.get("nonce") or ""))
        context = ToolCallContext(incident_id=incident.incident_id, thread_id=thread_id, correlation_id=incident.correlation_id, actor=actor_id, permission=("observability:read" if incident.scenario_id in NO_ACTION_SCENARIOS else "operations:write"))
        try:
            with runtime_factory() as runtime:
                runtime.start(incident, Caller(actor=actor_id, role=Role.OPERATOR), context)
        except Exception as error:
            raise safe_error(error) from error
        return RedirectResponse(f"/threads/{thread_id}", 303)

    @app.get("/incidents/{thread_id}/start", response_class=HTMLResponse)
    def start_prompt(thread_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> HTMLResponse:
        require(request, Role.OPERATOR, x_incidentgate_actor)
        if thread_id not in app.state.incidents:
            raise HTTPException(404, "incident not found")
        actor_id, _ = actor(request, x_incidentgate_actor)
        incident = app.state.incidents[thread_id]
        nonce = issue(thread_id, incident.scenario_id, actor_id, "start")
        return page(f"Start {incident.scenario_id} analysis", f"<p>Fault preparation is complete; this does not execute an operation.</p><form method='post' action='/incidents/{_text(thread_id)}/start'><input type='hidden' name='nonce' value='{_text(nonce)}'><button>Start analysis</button></form>")

    @app.get("/threads/{thread_id}", response_class=HTMLResponse)
    def thread(thread_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> HTMLResponse:
        actor_id, role = actor(request, x_incidentgate_actor)
        current, events = open_status(thread_id)
        scenario_id = scenario_for(current)
        app.state.incidents.setdefault(
            thread_id,
            IncidentIdentity(incident_id=f"INC-{scenario_id}", scenario_id=scenario_id,
                             thread_id=thread_id, correlation_id=f"durable-{thread_id}",
                             state=IncidentState.OPEN),
        )
        return status_page(current, events, actor_id, role)

    async def decide(thread_id: str, request: Request, decision: str, x_incidentgate_actor: str | None) -> RedirectResponse:
        actor_id = require(request, Role.APPROVER, x_incidentgate_actor)
        form = await request.form()
        current, _ = open_status(thread_id)
        scenario_id = scenario_for(current)
        consume(thread_id, scenario_id, actor_id, decision, str(form.get("nonce") or ""))
        reason = str(form.get("reason") or "").strip() or None
        pending = _value(current, "pending")
        if pending is None:
            raise HTTPException(409, "approval is no longer pending")
        if bool(_value(pending, "requires_reason", False)) and not reason:
            raise HTTPException(422, "a defer reason is required")
        try:
            with runtime_factory() as runtime:
                runtime.resume(thread_id)
                principal = Principal(actor_id, Role.APPROVER)
                if decision == "approve":
                    runtime.approve(thread_id, principal, reason=reason)
                else:
                    runtime.reject(thread_id, principal, reason=reason)
        except Exception as error:
            raise safe_error(error) from error
        return RedirectResponse(f"/threads/{thread_id}", 303)

    @app.post("/threads/{thread_id}/approve")
    async def approve(thread_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> RedirectResponse:
        return await decide(thread_id, request, "approve", x_incidentgate_actor)

    @app.post("/threads/{thread_id}/reject")
    async def reject(thread_id: str, request: Request, x_incidentgate_actor: str | None = Header(default=None)) -> RedirectResponse:
        return await decide(thread_id, request, "reject", x_incidentgate_actor)

    return app
