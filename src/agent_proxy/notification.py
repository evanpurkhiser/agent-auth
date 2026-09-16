"""Format signing context and deliver it through the local Telegram service."""

import json
import shlex
import socket
import urllib.request

from .protocol import RequestContext

NOTIFICATION_ENDPOINT = "https://bot.prk.network/"


def escape_markdown(text: str, *, code: bool = False) -> str:
    """Escape Telegram MarkdownV2 text or the contents of a code entity."""
    special = "\\`" if code else "\\_*[]()~`>#+-=|{}.!"
    return "".join(f"\\{char}" if char in special else char for char in text)


def send_notification(context: RequestContext, route: str) -> None:
    hostname = escape_markdown(socket.gethostname(), code=True)
    route = escape_markdown(route, code=True)
    command = escape_markdown(shlex.join(context.command), code=True)
    message = "\n\n".join(
        (
            f"🔐 {escape_markdown(context.reason)}",
            f"```command\n{command}\n```",
            rf"\(agent\-auth from `{hostname}` via `{route}`\)",
        )
    )
    request = urllib.request.Request(
        NOTIFICATION_ENDPOINT,
        data=json.dumps({"text": message, "parse_mode": "MarkdownV2"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=3):
        pass
