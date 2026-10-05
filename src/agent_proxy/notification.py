"""Deliver signing context to a configured notification command."""

import json
import socket
import subprocess

from .config import NotificationConfig
from .protocol import RequestContext


def send_notification(
    context: RequestContext, route: str, config: NotificationConfig
) -> None:
    """Pass a signing event to the configured command as JSON on standard input."""

    if config.command is None:
        return

    event = {
        "version": 1,
        "reason": context.reason,
        "command": list(context.command),
        "group_id": context.group_id,
        "route": route,
        "hostname": socket.gethostname(),
    }
    subprocess.run(
        config.command,
        input=json.dumps(event).encode(),
        stdout=subprocess.DEVNULL,
        check=True,
        timeout=config.timeout,
    )
