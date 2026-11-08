"""Structured (JSON) security logging. Never pass passwords, keys or tokens here."""

import json
import logging
import os
from datetime import datetime, timezone

from flask import has_request_context, request
from flask_login import current_user

logger = logging.getLogger("security")


class JsonFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        data.update(getattr(record, "fields", {}))
        if has_request_context():
            data["ip"] = request.remote_addr or "uknown"
            data["method"] = request.method
            data["path"] = request.path
        if record.exc_info:  # stack trace goes to the LOG only, never to the user
            data["trace"] = self.formatException(record.exc_info)
        return json.dumps(data)


def setup(app):
    handler = logging.FileHandler(os.path.join(app.instance_path, "security.log"))
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def log_event(event, level=logging.INFO, exc_info=False, **fields):
    if has_request_context() and current_user.is_authenticated:
        fields.setdefault("user_id", current_user.id)
    logger.log(level, event, exc_info=exc_info, extra={"fields": fields})