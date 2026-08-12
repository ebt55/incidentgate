from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from incidentgate.contracts import IncidentIdentity, IncidentState
from incidentgate.integration import PendingApproval
from incidentgate.ui import create_ui_app


class FakeController:
    def __init__(self) -> None:
        self.prepared = 0

    def prepare(self, scenario_id: str, thread_id: str, correlation_id: str) -> IncidentIdentity:
        self.prepared += 1
        return IncidentIdentity(
            incident_id=f"INC-{scenario_id}",
            scenario_id=scenario_id,
            thread_id=thread_id,
            correlation_id=correlation_id,
            state=IncidentState.OPEN,
        )


def pending_approval(**overrides: object) -> PendingApproval:
    """A real PendingApproval, not a look-alike.

    The previous fake was a SimpleNamespace that differed from the production
    contract in both directions: it carried monitor_rationale, which the real
    dataclass did not have, and omitted policy_decision, policy_reasons and
    monitor_suspicion, which the page read. That is why a page rendering four
    placeholders to every approver passed its tests. Using the real type means
    the dataclass rejects any future drift instead of absorbing it.
    """
    fields: dict[str, Any] = {
        "thread_id": "",
        "incident_id": "INC-D1",
        "action_hash": "a" * 64,
        "monitor_verdict": "defer",
        "monitor_rationale": "<monitor>",
        "monitor_suspicion": 0.42,
        "policy_decision": "require_approval",
        "policy_reasons": ("policy_valid", "<reason>"),
        "requires_reason": True,
        "evidence_ids": ("ev-safe",),
        "tool_name": "operations.rollback",
        "component": "api",
        "target_revision": "v1",
        "trace_id": "trace-safe",
        "trace_url": "javascript:alert(1)",
    }
    fields.update(overrides)
    return PendingApproval(**fields)  # type: ignore[arg-type]


class FakeRuntime:
    def __init__(self) -> None:
        self.pending = pending_approval()
        self.pending_threads: set[str] = set()
        self.started = self.approved = self.rejected = 0
        self.closes = 0
        self.results: dict[str, object] = {}
        self.last_reason = ""

    def start(self, incident: IncidentIdentity, operator: object, context: object) -> object:
        self.started += 1
        self.pending_threads.add(incident.thread_id)
        return self.pending

    def resume(self, thread_id: str) -> object:
        if thread_id not in self.pending_threads:
            raise ValueError("unknown D1 runtime thread")
        return self.status(thread_id)

    def status(self, thread_id: str) -> object:
        return SimpleNamespace(
            thread_id=thread_id,
            incident_id="INC-D1",
            pending=self.pending
            if thread_id in self.pending_threads and thread_id not in self.results
            else None,
            result=self.results.get(thread_id),
        )

    def approve(self, thread_id: str, approver: object, *, reason: str | None = None) -> object:
        self.approved += 1
        self.last_reason = reason or ""
        self.results[thread_id] = SimpleNamespace(
            final_state="resolved",
            approval=SimpleNamespace(decision="approve", reason=reason),
            operation=SimpleNamespace(status="succeeded", idempotency_key="idem-safe"),
            verification=SimpleNamespace(
                predicate="health is 200", passed=True, evidence_ids=("ev-fresh",)
            ),
            policy=SimpleNamespace(decision="require_approval"),
            monitor=SimpleNamespace(verdict="defer", rationale="<result-monitor>"),
            trace_id="trace-safe",
            trace_url="javascript:secret-token",
        )
        return self.status(thread_id)

    def reject(self, thread_id: str, approver: object, *, reason: str | None = None) -> object:
        self.rejected += 1
        self.results[thread_id] = SimpleNamespace(
            final_state="blocked",
            approval=SimpleNamespace(decision="reject"),
            operation=None,
            verification=None,
        )
        return self.status(thread_id)

    def timeline(self, incident_id: str, *, limit: int = 50) -> tuple[object, ...]:
        return (SimpleNamespace(timestamp="now", transition="policy", reason="safe <event>"),)


def client() -> tuple[TestClient, FakeRuntime, FakeController]:
    runtime, controller = FakeRuntime(), FakeController()

    @contextmanager
    def factory():
        try:
            yield runtime
        finally:
            runtime.closes += 1

    return TestClient(create_ui_app(factory, controller)), runtime, controller


def headers(actor: str) -> dict[str, str]:
    return {"X-Incidentgate-Actor": actor}


def nonce(page: str, position: int = 0) -> str:
    return page.split("name='nonce' value='")[position + 1].split("'")[0]


def login(test_client: TestClient, actor: str) -> None:
    response = test_client.post("/mock-login", data={"actor": actor}, follow_redirects=False)
    assert response.status_code == 303


def prepared_thread(test_client: TestClient) -> str:
    login(test_client, "operator-1")
    response = test_client.get("/")
    response = test_client.post(
        "/incidents/d1/prepare", data={"nonce": nonce(response.text)}, follow_redirects=False
    )
    return response.headers["location"].split("/")[2]


def start_thread(test_client: TestClient, thread: str) -> None:
    prompt = test_client.get(f"/incidents/{thread}/start")
    response = test_client.post(
        f"/incidents/{thread}/start", data={"nonce": nonce(prompt.text)}, follow_redirects=False
    )
    assert response.status_code == 303


def test_role_boundaries_unknown_identity_and_no_preapproval_execution() -> None:
    test_client, runtime, controller = client()
    assert test_client.get("/", headers=headers("nobody")).status_code == 200
    assert (
        test_client.post("/incidents/d1/prepare", headers=headers("approver-1")).status_code == 403
    )
    thread = prepared_thread(test_client)
    assert controller.prepared == 1 and runtime.started == 0
    assert (
        test_client.post(f"/incidents/{thread}/start", headers=headers("approver-1")).status_code
        == 403
    )
    start_thread(test_client, thread)
    assert runtime.started == 1 and runtime.approved == 0
    assert (
        test_client.post(f"/threads/{thread}/approve", headers=headers("operator-1")).status_code
        == 403
    )
    assert runtime.closes >= 1


def approver_view(test_client: TestClient) -> str:
    thread = prepared_thread(test_client)
    start_thread(test_client, thread)
    login(test_client, "approver-1")
    return test_client.get(f"/threads/{thread}").text


def test_pending_page_shows_the_real_policy_and_monitor_values() -> None:
    """The acceptance core: the approver sees what the gate actually decided.

    Every one of these assertions failed before the contract carried the data:
    the page rendered "Policy: requires human approval; reasons: -" and
    "rationale: unavailable; suspicion: unavailable" to every approver, on every
    pending incident, no matter what policy and the monitor had actually said.
    """
    page = approver_view(client()[0])

    assert "require_approval" in page, "the real policy decision must be shown"
    assert "policy_valid" in page, "the real policy reasons must be shown"
    assert "&lt;reason&gt;" in page, "every real reason is shown, and escaped"
    assert "&lt;monitor&gt;" in page, "the real monitor rationale must be shown"
    assert "0.42" in page, "the real monitor suspicion score must be shown"

    # Nothing about this pending approval is absent, so nothing may be marked
    # absent. This is the assertion that would have caught the original defect.
    assert "unavailable" not in page
    assert "requires human approval" not in page, "the fabricated default is gone"


def test_pending_page_marks_absent_monitor_values_instead_of_inventing_them() -> None:
    """No plausible defaults: absence is reported as absence, distinctly."""
    test_client, runtime, _ = client()
    runtime.pending = pending_approval(
        monitor_verdict=None,
        monitor_rationale=None,
        monitor_suspicion=None,
        requires_reason=False,
    )
    page = approver_view(test_client)

    assert page.count("unavailable") == 3, "verdict, rationale and suspicion are each absent"
    # Policy is still known, so it must not be swept into the same marker.
    assert "require_approval" in page and "policy_valid" in page


def test_a_zero_suspicion_score_is_shown_and_not_mistaken_for_absent() -> None:
    """0.0 is a real score from a real monitor, and the lowest-suspicion one.

    A truthiness check would render it as "unavailable" and tell the approver the
    monitor had said nothing, when in fact it had said the action looks clean.
    """
    test_client, runtime, _ = client()
    runtime.pending = pending_approval(monitor_suspicion=0.0)
    page = approver_view(test_client)

    assert "suspicion: 0.0" in page
    assert "unavailable" not in page


def test_pending_page_reports_absent_policy_reasons_without_fabricating_one() -> None:
    """PolicyOutcome.reasons has min_length=1, so empty unambiguously means absent."""
    test_client, runtime, _ = client()
    runtime.pending = pending_approval(policy_decision=None, policy_reasons=())
    page = approver_view(test_client)

    assert "reasons: -" in page, "an absent reason list is marked, not invented"
    assert "requires human approval" not in page


def test_defer_reason_nonce_and_completed_timeline_are_safe() -> None:
    test_client, runtime, _ = client()
    thread = prepared_thread(test_client)
    start_thread(test_client, thread)
    login(test_client, "approver-1")
    pending = test_client.get(f"/threads/{thread}")
    assert "rollback api from v2 to v1" in pending.text
    assert "safe &lt;event&gt;" in pending.text
    assert "&lt;monitor&gt;" in pending.text and "javascript:" not in pending.text
    assert "token" not in pending.text.lower() and "raw-log" not in pending.text.lower()
    approval_nonce = nonce(pending.text)
    assert (
        test_client.post(f"/threads/{thread}/approve", data={"nonce": approval_nonce}).status_code
        == 422
    )
    assert (
        test_client.post(
            f"/threads/{thread}/approve", data={"nonce": approval_nonce, "reason": "<ok>"}
        ).status_code
        == 403
    )
    pending = test_client.get(f"/threads/{thread}")
    approval_nonce = nonce(pending.text)
    assert (
        test_client.post(
            f"/threads/{thread}/approve",
            data={"nonce": approval_nonce, "reason": "<ok>"},
            follow_redirects=False,
        ).status_code
        == 303
    )
    login(test_client, "observer-1")
    done = test_client.get(f"/threads/{thread}")
    assert runtime.approved == 1 and "Fresh recovery" in done.text and "ev-fresh" in done.text
    assert "&lt;ok&gt;" in done.text and "&lt;result-monitor&gt;" in done.text
    assert "javascript:" not in done.text and "token" not in done.text.lower()


def test_nonce_is_bound_to_thread() -> None:
    test_client, _, _ = client()
    first, second = prepared_thread(test_client), prepared_thread(test_client)
    for thread in (first, second):
        start_thread(test_client, thread)
    login(test_client, "approver-1")
    page = test_client.get(f"/threads/{first}")
    approval_nonce = nonce(page.text)
    response = test_client.post(
        f"/threads/{second}/reject", data={"nonce": approval_nonce, "reason": "no"}
    )
    assert response.status_code == 403


def test_prepare_and_start_nonces_are_action_scoped_and_one_use() -> None:
    test_client, runtime, _ = client()
    login(test_client, "operator-1")
    home = test_client.get("/")
    prepare_nonce = nonce(home.text)
    assert test_client.post("/incidents/d1/prepare", data={}).status_code == 403
    response = test_client.post(
        "/incidents/d1/prepare", data={"nonce": prepare_nonce}, follow_redirects=False
    )
    assert response.status_code == 303
    assert (
        test_client.post("/incidents/d1/prepare", data={"nonce": prepare_nonce}).status_code == 403
    )
    thread = response.headers["location"].split("/")[2]
    prompt = test_client.get(f"/incidents/{thread}/start")
    start_nonce = nonce(prompt.text)
    assert (
        test_client.post(f"/incidents/{thread}/start", data={"nonce": prepare_nonce}).status_code
        == 403
    )
    assert runtime.started == 0
    assert (
        test_client.post(
            f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False
        ).status_code
        == 303
    )
    assert (
        test_client.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}).status_code
        == 403
    )
