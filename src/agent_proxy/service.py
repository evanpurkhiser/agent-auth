"""Consume connection context, notify on signing, and relay agent packets."""

import logging
import sys
import threading
from typing import BinaryIO

from .config import ConfigError, RoutingConfig, load_config
from .diagnostics import warn_context_required
from .notification import send_notification
from .protocol import (
    CONTEXT_EXTENSION,
    SSH_AGENT_FAILURE,
    ContextRequiredError,
    ProtocolError,
    extension_name,
    is_sign_request,
    read_initial_context,
    read_packet,
    write_packet,
)
from .routing import open_backend

LOG = logging.getLogger("ssh-agent-proxy")


def relay_agent_connection(
    client_reader: BinaryIO,
    client_writer: BinaryIO,
    client_fd: int | None = None,
    routing_config: RoutingConfig | None = None,
) -> None:
    """Read initial context and relay one SSH-agent connection."""

    context, packet = read_initial_context(client_reader, client_writer)
    if packet is None and context is None:
        raise ProtocolError("client closed before sending an SSH-agent packet")
    if context is None:
        write_packet(client_writer, SSH_AGENT_FAILURE)
        warn_context_required(client_fd)

        raise ContextRequiredError("SSH agent access requires ssh-agent-ctx")

    backend = open_backend(context.route, routing_config)
    response_error: list[Exception] = []

    def relay_responses() -> None:
        try:
            while (packet := read_packet(backend.reader)) is not None:
                write_packet(client_writer, packet)
        except (EOFError, OSError, ProtocolError) as error:
            response_error.append(error)

    try:
        responses = threading.Thread(
            target=relay_responses, name="agent-proxy-responses"
        )
        responses.start()
        notified = False

        try:
            while (
                packet is not None or (packet := read_packet(client_reader)) is not None
            ):
                # read_initial_context consumes a leading context packet, so any
                # context encountered during the relay is out of order.
                if extension_name(packet) == CONTEXT_EXTENSION:
                    raise ProtocolError("request context must be the first packet")

                if not notified and is_sign_request(packet):
                    try:
                        send_notification(context, backend.label)
                    except (OSError, TimeoutError):
                        LOG.warning("failed to send context notification")
                    notified = True

                write_packet(backend.writer, packet)
                packet = None
        finally:
            backend.close_input()
            responses.join(timeout=5)

        if response_error:
            raise response_error[0]
    finally:
        backend.close()


def run_proxy(routing_config: RoutingConfig | None = None) -> int:
    """Serve one systemd-accepted SSH-agent connection."""

    try:
        relay_agent_connection(
            sys.stdin.buffer,
            sys.stdout.buffer,
            sys.stdin.fileno(),
            routing_config,
        )
    except (EOFError, OSError, ProtocolError, RuntimeError) as error:
        LOG.error("%s", error)
        return 1

    return 0


def main() -> int:
    """Configure service logging and serve the accepted connection."""

    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        config = load_config()
    except (ConfigError, OSError) as error:
        LOG.error("failed to load configuration: %s", error)
        return 1

    return run_proxy(config.routing)


if __name__ == "__main__":
    raise SystemExit(main())
