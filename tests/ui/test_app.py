from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

from fastapi.testclient import TestClient

from triage_agent_lab.contracts import IncidentIdentity
from triage_agent_lab.ui import create_ui_app


class FakeController:
    def __init__(self) -> None:
        self.prepared = 0

    def prepare_d1(self) -> None:
        self.prepared += 1


class FakeRuntime:
    def __init__(self) -> None:
        self.pending = SimpleNamespace(
            thread_id="", incident_id="INC-D1", component="api", target_revision="v1",
            evidence_ids=("ev-safe",), monitor_verdict="defer", requires_reason=True,
            monitor_rationale="<monitor>", trace_id="trace-safe", trace_url="javascript:alert(1)",
        )
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
        return SimpleNamespace(thread_id=thread_id, incident_id="INC-D1", pending=self.pending if thread_id in self.pending_threads and thread_id not in self.results else None, result=self.results.get(thread_id))

    def approve(self, thread_id: str, approver: object, *, reason: str | None = None) -> object:
        self.approved += 1
        self.last_reason = reason or ""
        self.results[thread_id] = SimpleNamespace(
            final_state="resolved", approval=SimpleNamespace(decision="approve", reason=reason),
            operation=SimpleNamespace(status="succeeded", idempotency_key="idem-safe"),
            verification=SimpleNamespace(predicate="health is 200", passed=True, evidence_ids=("ev-fresh",)),
            policy=SimpleNamespace(decision="require_approval"),
            monitor=SimpleNamespace(verdict="defer", rationale="<result-monitor>"),
            trace_id="trace-safe", trace_url="javascript:secret-token",
        )
        return self.status(thread_id)

    def reject(self, thread_id: str, approver: object, *, reason: str | None = None) -> object:
        self.rejected += 1
        self.results[thread_id] = SimpleNamespace(final_state="blocked", approval=SimpleNamespace(decision="reject"), operation=None, verification=None)
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
    return {"X-D1-Actor": actor}


def nonce(page: str, position: int = 0) -> str:
    return page.split("name='nonce' value='")[position + 1].split("'")[0]


def login(test_client: TestClient, actor: str) -> None:
    response = test_client.post("/mock-login", data={"actor": actor}, follow_redirects=False)
    assert response.status_code == 303


def prepared_thread(test_client: TestClient) -> str:
    login(test_client, "operator-1")
    response = test_client.get("/")
    response = test_client.post("/incidents/d1/prepare", data={"nonce": nonce(response.text)}, follow_redirects=False)
    return response.headers["location"].split("/")[2]


def start_thread(test_client: TestClient, thread: str) -> None:
    prompt = test_client.get(f"/incidents/{thread}/start")
    response = test_client.post(f"/incidents/{thread}/start", data={"nonce": nonce(prompt.text)}, follow_redirects=False)
    assert response.status_code == 303


def test_role_boundaries_unknown_identity_and_no_preapproval_execution() -> None:
    test_client, runtime, controller = client()
    assert test_client.get("/", headers=headers("nobody")).status_code == 200
    assert test_client.post("/incidents/d1/prepare", headers=headers("approver-1")).status_code == 403
    thread = prepared_thread(test_client)
    assert controller.prepared == 1 and runtime.started == 0
    assert test_client.post(f"/incidents/{thread}/start", headers=headers("approver-1")).status_code == 403
    start_thread(test_client, thread)
    assert runtime.started == 1 and runtime.approved == 0
    assert test_client.post(f"/threads/{thread}/approve", headers=headers("operator-1")).status_code == 403
    assert runtime.closes >= 1


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
    assert test_client.post(f"/threads/{thread}/approve", data={"nonce": approval_nonce}).status_code == 422
    assert test_client.post(f"/threads/{thread}/approve", data={"nonce": approval_nonce, "reason": "<ok>"}).status_code == 403
    pending = test_client.get(f"/threads/{thread}")
    approval_nonce = nonce(pending.text)
    assert test_client.post(f"/threads/{thread}/approve", data={"nonce": approval_nonce, "reason": "<ok>"}, follow_redirects=False).status_code == 303
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
    response = test_client.post(f"/threads/{second}/reject", data={"nonce": approval_nonce, "reason": "no"})
    assert response.status_code == 403


def test_prepare_and_start_nonces_are_action_scoped_and_one_use() -> None:
    test_client, runtime, _ = client()
    login(test_client, "operator-1")
    home = test_client.get("/")
    prepare_nonce = nonce(home.text)
    assert test_client.post("/incidents/d1/prepare", data={}).status_code == 403
    response = test_client.post("/incidents/d1/prepare", data={"nonce": prepare_nonce}, follow_redirects=False)
    assert response.status_code == 303
    assert test_client.post("/incidents/d1/prepare", data={"nonce": prepare_nonce}).status_code == 403
    thread = response.headers["location"].split("/")[2]
    prompt = test_client.get(f"/incidents/{thread}/start")
    start_nonce = nonce(prompt.text)
    assert test_client.post(f"/incidents/{thread}/start", data={"nonce": prepare_nonce}).status_code == 403
    assert runtime.started == 0
    assert test_client.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}, follow_redirects=False).status_code == 303
    assert test_client.post(f"/incidents/{thread}/start", data={"nonce": start_nonce}).status_code == 403
