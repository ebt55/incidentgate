"""Local-only FastAPI fault boundary for the deterministic D1 lab target."""

from typing import Protocol, cast

from fastapi import FastAPI, Header, HTTPException, Response, status

ADMIN_HEADER = "X-Incidentgate-Lab-Admin"


class TargetRepository(Protocol):
    def state(self) -> dict[str, object]: ...

    def reset_d1(self) -> None: ...

    def inject_d1(self) -> None: ...


def create_app(
    repository: TargetRepository, admin_token: str = "incidentgate-local-admin"
) -> FastAPI:
    """Create an in-process-only controller; callers must supply explicit mock admin auth."""
    app = FastAPI(title="D1 Lab Target", docs_url=None, redoc_url=None)

    def require_admin(value: str | None) -> None:
        if value != admin_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="mock admin auth required"
            )

    def target_status() -> dict[str, object]:
        try:
            return repository.state()
        except RuntimeError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(error)
            ) from error

    @app.get("/health")
    def health(response: Response) -> dict[str, object]:
        current = target_status()
        response.status_code = cast(int, current["health_status"])
        return current

    @app.get("/deployment/status")
    def deployment_status() -> dict[str, object]:
        return target_status()

    @app.post("/admin/reset")
    def reset(x_incidentgate_lab_admin: str | None = Header(default=None)) -> dict[str, object]:
        require_admin(x_incidentgate_lab_admin)
        repository.reset_d1()
        return repository.state()

    @app.post("/admin/inject")
    def inject(x_incidentgate_lab_admin: str | None = Header(default=None)) -> dict[str, object]:
        require_admin(x_incidentgate_lab_admin)
        repository.inject_d1()
        return repository.state()

    return app
