"""Load agent-auth configuration from TOML and environment overrides."""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

DEFAULT_CONFIG_PATH = Path("/etc/agent-auth/config.toml")


class ConfigError(ValueError):
    """Describe an invalid agent-auth configuration."""


@dataclass(frozen=True, slots=True)
class RoutingConfig:
    """Settings used to discover and connect to signing backends."""

    computer_pattern: str = r"macbook-.*"
    ssh_key: Path = Path("/etc/ssh-agent-proxy-key")
    ssh_user: str = "evan"
    agent_witness_socket: Path = Path("/run/agent-witness/agent.sock")


DEFAULT_ROUTING_CONFIG = RoutingConfig()


@dataclass(frozen=True, slots=True)
class Config:
    """Top-level agent-auth configuration."""

    routing: RoutingConfig = DEFAULT_ROUTING_CONFIG


def _routing_values(document: object) -> dict[str, str]:
    if not isinstance(document, dict):
        raise ConfigError("configuration must be a TOML table")

    unknown_sections = document.keys() - {"routing"}
    if unknown_sections:
        names = ", ".join(sorted(unknown_sections))
        raise ConfigError(f"unknown configuration section: {names}")

    routing = document.get("routing", {})
    if not isinstance(routing, dict):
        raise ConfigError("routing must be a TOML table")

    fields = {
        "computer_pattern",
        "ssh_key",
        "ssh_user",
        "agent_witness_socket",
    }
    unknown_fields = routing.keys() - fields
    if unknown_fields:
        names = ", ".join(sorted(unknown_fields))
        raise ConfigError(f"unknown routing setting: {names}")

    for name, value in routing.items():
        if not isinstance(value, str) or not value:
            raise ConfigError(f"routing.{name} must be a non-empty string")

    return routing


def load_config(
    path: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> Config:
    """Load routing settings, allowing environment variables to override TOML."""

    environ = os.environ if environment is None else environment
    config_path = path
    if config_path is None:
        config_path = Path(environ.get("AGENT_AUTH_CONFIG", DEFAULT_CONFIG_PATH))
    optional = path is None and "AGENT_AUTH_CONFIG" not in environ

    try:
        with config_path.open("rb") as config_file:
            values = _routing_values(tomllib.load(config_file))
    except FileNotFoundError:
        if not optional:
            raise ConfigError(f"configuration file does not exist: {config_path}")
        values = {}
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"invalid TOML in {config_path}: {error}") from error

    computer_pattern = environ.get(
        "AGENT_AUTH_TAILSCALE_MACBOOK_PATTERN",
        values.get("computer_pattern", DEFAULT_ROUTING_CONFIG.computer_pattern),
    )
    ssh_key = environ.get(
        "AGENT_AUTH_SSH_KEY",
        values.get("ssh_key", str(DEFAULT_ROUTING_CONFIG.ssh_key)),
    )
    ssh_user = environ.get(
        "AGENT_AUTH_SSH_USER",
        values.get("ssh_user", DEFAULT_ROUTING_CONFIG.ssh_user),
    )
    agent_witness_socket = environ.get(
        "AGENT_AUTH_AGENT_WITNESS_SOCKET",
        values.get(
            "agent_witness_socket", str(DEFAULT_ROUTING_CONFIG.agent_witness_socket)
        ),
    )

    try:
        re.compile(computer_pattern)
    except re.error as error:
        raise ConfigError(f"routing.computer_pattern is invalid: {error}") from error

    return Config(
        routing=RoutingConfig(
            computer_pattern=computer_pattern,
            ssh_key=Path(ssh_key),
            ssh_user=ssh_user,
            agent_witness_socket=Path(agent_witness_socket),
        )
    )
