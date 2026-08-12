from fastapi.testclient import TestClient

from incidentgate.lab.app import ADMIN_HEADER, create_app


class FakeTarget:
    def __init__(self) -> None:
        self.current = {"revision": "v1", "health_status": 200, "mutation_count": 0}

    def state(self) -> dict[str, object]:
        return self.current

    def reset_d1(self) -> None:
        self.current = {"revision": "v1", "health_status": 200, "mutation_count": 0}

    def inject_d1(self) -> None:
        self.current = {"revision": "v2", "health_status": 500, "mutation_count": 0}


def test_local_fault_boundary_requires_mock_admin_auth_and_reflects_target() -> None:
    client = TestClient(create_app(FakeTarget(), "test-admin"))
    assert client.get("/health").status_code == 200
    assert client.get("/deployment/status").json()["revision"] == "v1"
    assert client.post("/admin/inject").status_code == 403
    response = client.post("/admin/inject", headers={ADMIN_HEADER: "test-admin"})
    assert response.status_code == 200
    assert response.json()["health_status"] == 500
    assert client.get("/health").status_code == 500
    assert (
        client.post("/admin/reset", headers={ADMIN_HEADER: "test-admin"}).json()["revision"] == "v1"
    )
