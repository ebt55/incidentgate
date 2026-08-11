"""ASGI entrypoint for the localhost-only D1 approval UI service."""

from .app import create_host_app

app = create_host_app()
