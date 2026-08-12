"""Container entrypoint for the local D1 target."""

import os

from .app import create_app
from .repository import LabRepository

repository = LabRepository(os.environ["DATABASE_URL"])
repository.migrate()
repository.initialize_d1_if_absent()
app = create_app(repository, os.environ["INCIDENTGATE_LAB_ADMIN_TOKEN"])
