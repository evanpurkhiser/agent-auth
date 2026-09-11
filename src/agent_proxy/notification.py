"""Format signing context and deliver it through the local Telegram service."""

import json
import shlex
import socket
import urllib.request

from .protocol import RequestContext

NOTIFICATION_ENDPOINT = "https://bot.prk.network/"


def send_notification(context: RequestContext, route: str) -> None:
    message = "\n".join(
        (
            f"🔐 Agent key request ({socket.gethostname()} via {route})",
            f"Reason: {context.reason}",
            f"Command: {shlex.join(context.command)}",
        )
    )
    request = urllib.request.Request(
        NOTIFICATION_ENDPOINT,
        data=json.dumps({"text": message}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3):
        pass
