"""Discover ready MacBooks and open the selected SSH-agent backend."""

from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import BinaryIO

from .config import DEFAULT_ROUTING_CONFIG, RoutingConfig

# The remote forced command handles this as a readiness probe instead of
# forwarding the connection to its SSH agent.
STATUS_REQUEST = b"AGENT-PROXY-STATUS/1\n"

LOG = logging.getLogger("ssh-agent-proxy")


@dataclass(frozen=True, slots=True)
class MacBookRoute:
    """Address an online MacBook by its tailnet DNS name and Tailscale IP."""

    name: str
    address: str

    @property
    def hostname(self) -> str:
        """Return the hostname portion of the tailnet DNS name."""

        return self.name.removesuffix(".").split(".", 1)[0]


@dataclass(slots=True)
class Backend:
    """Own the streams and process or socket for one agent relay backend."""

    label: str
    reader: BinaryIO
    writer: BinaryIO
    process: subprocess.Popen[bytes] | None = None
    sock: socket.socket | None = None

    def close_input(self) -> None:
        """Signal EOF to the backend while leaving its output readable."""

        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

        self.writer.close()

    def close(self) -> None:
        """Close backend resources and reap its SSH process when present."""

        if not self.writer.closed:
            self.close_input()
        self.reader.close()

        if self.sock is not None:
            self.sock.close()

        if self.process is None:
            return

        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=2)


def parse_macbook_routes(
    status: object, pattern: str = DEFAULT_ROUTING_CONFIG.computer_pattern
) -> list[MacBookRoute]:
    """Extract matching online MacBooks in most-recently-active order."""

    if not isinstance(status, dict) or not isinstance(status.get("Peer"), dict):
        return []

    matcher = re.compile(pattern)
    routes: list[tuple[str, MacBookRoute]] = []
    for peer in status["Peer"].values():
        if not isinstance(peer, dict) or peer.get("Online") is not True:
            continue

        name = peer.get("DNSName")
        addresses = peer.get("TailscaleIPs")
        if (
            not isinstance(name, str)
            or matcher.search(name) is None
            or not isinstance(addresses, list)
            or not addresses
            or not isinstance(addresses[0], str)
        ):
            continue

        handshake = peer.get("LastHandshake")
        if not isinstance(handshake, str) or handshake == "0001-01-01T00:00:00Z":
            handshake = ""
        routes.append((handshake, MacBookRoute(name.removesuffix("."), addresses[0])))

    routes.sort(key=lambda route: route[0], reverse=True)
    return [route for _, route in routes]


def opt(**options: str | int) -> list[str]:
    """Format keyword arguments as OpenSSH configuration options."""

    return [
        argument
        for name, value in options.items()
        for argument in ("-o", f"{name}={value}")
    ]


def ssh_options(config: RoutingConfig | None = None) -> list[str]:
    """Build SSH arguments shared by readiness and relay connections."""

    config = config or RoutingConfig()

    return [
        "-T",
        "-i",
        str(config.ssh_key),
        "-l",
        config.ssh_user,
        *opt(IdentitiesOnly="yes"),
        *opt(StrictHostKeyChecking="accept-new"),
        *opt(BatchMode="yes"),
    ]


def find_ready_macbook(
    hostname: str | None = None,
    config: RoutingConfig | None = None,
) -> MacBookRoute | None:
    """Return the requested or most recently active ready MacBook."""

    config = config or RoutingConfig()

    try:
        result = subprocess.run(
            ["tailscale", "status", "--json"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        routes = parse_macbook_routes(
            json.loads(result.stdout), config.computer_pattern
        )
    except (OSError, re.error, subprocess.SubprocessError, json.JSONDecodeError):
        return None

    candidates = routes
    if hostname is not None:
        candidates = [route for route in routes if route.hostname == hostname]

    for route in candidates:
        try:
            probe = subprocess.run(
                [
                    "ssh",
                    *ssh_options(config),
                    *opt(ConnectTimeout=1),
                    *opt(ConnectionAttempts=1),
                    route.address,
                ],
                input=STATUS_REQUEST,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            continue

        if probe.returncode == 0 and probe.stdout.rstrip(b"\r\n") == b"ready":
            return route

    return None


def open_agent_witness(config: RoutingConfig | None = None) -> Backend:
    """Open the local agent-witness backend."""

    config = config or RoutingConfig()

    if not config.agent_witness_socket.is_socket():
        raise RuntimeError("agent-witness socket is unavailable")

    agent_socket = socket.socket(socket.AF_UNIX)
    agent_socket.connect(str(config.agent_witness_socket))
    return Backend(
        "agent-witness",
        agent_socket.makefile("rb", buffering=0),
        agent_socket.makefile("wb", buffering=0),
        sock=agent_socket,
    )


def open_backend(
    requested_route: str | None = None,
    config: RoutingConfig | None = None,
) -> Backend:
    """Open the requested route or automatically select a ready backend."""

    config = config or RoutingConfig()

    if requested_route == "agent-witness":
        LOG.info("using agent-witness")
        return open_agent_witness(config)

    route = find_ready_macbook(requested_route, config)
    if route is None:
        if requested_route is not None:
            raise RuntimeError(f"requested route {requested_route!r} is unavailable")

        LOG.info("no MacBook is ready, using agent-witness")
        return open_agent_witness(config)

    LOG.info("using %s", route.name)
    process = subprocess.Popen(
        ["ssh", *ssh_options(config), *opt(ConnectTimeout=5), route.address],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    if process.stdin is None or process.stdout is None:
        raise RuntimeError("failed to open SSH relay pipes")
    return Backend(
        route.hostname,
        process.stdout,
        process.stdin,
        process=process,
    )
