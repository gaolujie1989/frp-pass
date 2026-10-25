"""Gunicorn entry point; invalid configuration prevents startup."""

import logging
import os

from .app import Application
from .config import Settings

logging.basicConfig(level=logging.INFO, format="%(message)s")
application = Application(
    Settings.from_file(
        os.environ.get("FRP_AUTH_CONFIG", "/config/config.toml"),
        public_origin=os.environ.get("PUBLIC_ORIGIN"),
    )
)
