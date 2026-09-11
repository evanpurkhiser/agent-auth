"""Report rejected raw agent connections to their controlling terminal."""

import logging
import os
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

LOG = logging.getLogger("ssh-agent-proxy")
CONTEXT_REQUIRED_MESSAGE = (
    "[agent-auth] Run this command with ssh-agent-ctx to use the SSH agent\n"
)


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """Identify the process connected to the accepted Unix socket."""

    pid: int
    uid: int
    gid: int


def peer_credentials(socket_fd: int) -> PeerCredentials:
    """Read Linux peer credentials from an accepted Unix socket."""

    size = struct.calcsize("3i")
    with socket.fromfd(socket_fd, socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)

    return PeerCredentials(*struct.unpack("3i", credentials))


def process_name(pid: int) -> str:
    """Read a process name for diagnostics, falling back when it has exited."""

    try:
        return Path(f"/proc/{pid}/comm").read_text().strip()
    except OSError:
        return "unknown"


def write_peer_tty(pid: int, message: str) -> bool:
    """Write to the first standard descriptor backed by the peer's TTY."""

    for descriptor in (2, 1, 0):
        path = f"/proc/{pid}/fd/{descriptor}"
        try:
            if not os.readlink(path).startswith("/dev/"):
                continue

            tty_fd = os.open(path, os.O_WRONLY | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError:
            continue

        try:
            if not os.isatty(tty_fd):
                continue

            os.write(tty_fd, message.encode())
            return True
        except OSError:
            continue
        finally:
            os.close(tty_fd)

    return False


def warn_context_required(socket_fd: int | None) -> None:
    """Log a raw connection rejection and notify its TTY when available."""

    if socket_fd is None:
        return

    try:
        peer = peer_credentials(socket_fd)
    except OSError as error:
        LOG.warning("rejected raw SSH-agent connection: peer unavailable: %s", error)
        return

    notified = write_peer_tty(peer.pid, CONTEXT_REQUIRED_MESSAGE)
    LOG.warning(
        "rejected raw SSH-agent connection from "
        "pid=%(pid)d uid=%(uid)d process=%(process)s tty=%(tty)s",
        {
            "pid": peer.pid,
            "uid": peer.uid,
            "process": process_name(peer.pid),
            "tty": "notified" if notified else "unavailable",
        },
    )
