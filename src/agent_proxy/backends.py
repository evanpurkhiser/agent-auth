"""Signing backend interfaces and concrete connection implementations."""

from __future__ import annotations

import socket
import subprocess
from contextlib import ExitStack
from dataclasses import dataclass
from typing import BinaryIO, Protocol

from .config import RoutingConfig
from .protocol import SSH_AGENT_SUCCESS, ProtocolError, RequestContext, read_packet

# The remote forced command handles this as a readiness probe instead of
# forwarding the connection to its SSH agent.
STATUS_REQUEST = b"AGENT-PROXY-STATUS/1\n"


@dataclass(slots=True)
class AgentConnection:
    """Own the streams and resources for an open agent relay connection."""

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


class AgentBackend(Protocol):
    """A configured destination capable of serving SSH-agent requests."""

    @property
    def name(self) -> str:
        """Return the route name presented to callers and notifications."""

        ...

    def is_ready(self) -> bool:
        """Return whether this backend can currently serve requests."""

        ...

    def connect(self, context: RequestContext) -> AgentConnection:
        """Open a relay connection for a contextualized request."""

        ...


def opt(**options: str | int) -> list[str]:
    """Format keyword arguments as OpenSSH configuration options."""

    return [
        argument
        for name, value in options.items()
        for argument in ("-o", f"{name}={value}")
    ]


def ssh_options(config: RoutingConfig) -> list[str]:
    """Build SSH arguments shared by readiness and relay connections."""

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


@dataclass(frozen=True, slots=True)
class SshAgentBackend:
    """Connect to an SSH-agent relay through an SSH forced command."""

    name: str
    address: str
    config: RoutingConfig

    def is_ready(self) -> bool:
        try:
            probe = subprocess.run(
                [
                    "ssh",
                    *ssh_options(self.config),
                    *opt(ConnectTimeout=1),
                    *opt(ConnectionAttempts=1),
                    self.address,
                ],
                input=STATUS_REQUEST,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=2,
            )
        except (OSError, subprocess.SubprocessError):
            return False

        return probe.returncode == 0 and probe.stdout.rstrip(b"\r\n") == b"ready"

    def connect(self, context: RequestContext) -> AgentConnection:
        # The connection accepts context now so it can be forwarded by the remote
        # relay protocol without changing the router or service API.
        del context

        process = subprocess.Popen(
            [
                "ssh",
                *ssh_options(self.config),
                *opt(ConnectTimeout=5),
                self.address,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("failed to open SSH relay pipes")

        return AgentConnection(process.stdout, process.stdin, process=process)


@dataclass(frozen=True, slots=True)
class AgentWitnessBackend:
    """Connect to an Agent Witness Unix socket."""

    config: RoutingConfig
    name: str = "agent-witness"

    def is_ready(self) -> bool:
        return self.config.agent_witness_socket.is_socket()

    def connect(self, context: RequestContext) -> AgentConnection:
        if not self.is_ready():
            raise RuntimeError("agent-witness socket is unavailable")

        try:
            packet = subprocess.run(
                [
                    "agent-witness",
                    "write-context",
                    f"--reason={context.reason}",
                    f"--groupId={context.group_id}",
                    "--",
                    *context.command,
                ],
                stdout=subprocess.PIPE,
                check=True,
                timeout=5,
            ).stdout
        except subprocess.SubprocessError as error:
            raise RuntimeError(
                "agent-witness failed to write request context"
            ) from error

        with ExitStack() as resources:
            agent_socket = resources.enter_context(socket.socket(socket.AF_UNIX))
            agent_socket.settimeout(5)
            agent_socket.connect(str(self.config.agent_witness_socket))
            reader = resources.enter_context(agent_socket.makefile("rb", buffering=0))
            writer = resources.enter_context(agent_socket.makefile("wb", buffering=0))
            agent_socket.sendall(packet)

            if read_packet(reader) != SSH_AGENT_SUCCESS:
                raise ProtocolError("agent-witness rejected request context")

            agent_socket.settimeout(None)
            connection = AgentConnection(reader, writer, sock=agent_socket)
            resources.pop_all()
            return connection
