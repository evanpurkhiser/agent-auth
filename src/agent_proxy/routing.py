"""Discover and select a ready SSH-agent backend."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass

from .backends import AgentBackend, AgentWitnessBackend, SshAgentBackend
from .config import DEFAULT_ROUTING_CONFIG, RoutingConfig

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


def find_ready_macbook(
    hostname: str | None = None,
    config: RoutingConfig | None = None,
) -> SshAgentBackend | None:
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
        backend = SshAgentBackend(route.hostname, route.address, config)
        if backend.is_ready():
            return backend

    return None


def select_backend(
    requested_route: str | None = None,
    config: RoutingConfig | None = None,
) -> AgentBackend:
    """Select the requested route or the first ready backend."""

    config = config or RoutingConfig()

    if requested_route == "agent-witness":
        LOG.info("using agent-witness")
        return AgentWitnessBackend(config)

    route = find_ready_macbook(requested_route, config)
    if route is None:
        if requested_route is not None:
            raise RuntimeError(f"requested route {requested_route!r} is unavailable")

        LOG.info("no MacBook is ready, using agent-witness")
        return AgentWitnessBackend(config)

    LOG.info("using %s", route.name)
    return route
