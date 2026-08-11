"""Container entrypoint for the local D1 target."""

import os

from .app import create_app
from .repository import D1Repository

repository = D1Repository(os.environ["DATABASE_URL"])
repository.migrate()
repository.initialize_d1_if_absent()
app = create_app(repository, os.environ["D1_LAB_ADMIN_TOKEN"])
