"""Own the context CLI, temporary agent socket, handshake, and byte relay."""

import argparse
import logging
import os
import selectors
import socket
import subprocess
import tempfile
import threading
import uuid
from collections.abc import Sequence
from pathlib import Path

from .protocol import (
    SSH_AGENT_SUCCESS,
    ProtocolError,
    RequestContext,
    encode_context,
    read_packet,
)

LOG = logging.getLogger("ssh-agent-ctx")


def relay_sockets(left: socket.socket, right: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(left, selectors.EVENT_READ, right)
    selector.register(right, selectors.EVENT_READ, left)

    try:
        while selector.get_map():
            for key, _ in selector.select():
                source: socket.socket = key.fileobj
                destination: socket.socket = key.data
                data = source.recv(64 * 1024)
                if data:
                    destination.sendall(data)
                    continue

                selector.unregister(source)
                try:
                    destination.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
    finally:
        selector.close()


def serve_context_connection(
    downstream: socket.socket, upstream_path: str, packet: bytes
) -> None:
    with downstream, socket.socket(socket.AF_UNIX) as upstream:
        try:
            upstream.connect(upstream_path)
            upstream.sendall(packet)
            response = read_packet(upstream.makefile("rb", buffering=0))
            if response != SSH_AGENT_SUCCESS:
                raise RuntimeError("SSH agent proxy rejected request context")
            relay_sockets(downstream, upstream)
        except (EOFError, OSError, ProtocolError, RuntimeError) as error:
            LOG.error("%s", error)


def run_with_context(context: RequestContext, upstream_path: str) -> int:
    packet = encode_context(context)
    handlers: list[threading.Thread] = []
    stop = threading.Event()

    with tempfile.TemporaryDirectory(prefix="ssh-agent-ctx-") as directory:
        socket_path = Path(directory, "agent.sock")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(socket_path))
            socket_path.chmod(0o600)
            listener.listen()
            listener.settimeout(0.2)

            environment = os.environ.copy()
            environment["SSH_AUTH_SOCK"] = str(socket_path)
            process = subprocess.Popen(context.command, env=environment)

            def accept_connections() -> None:
                while not stop.is_set():
                    try:
                        downstream, _ = listener.accept()
                    except TimeoutError:
                        continue
                    except OSError:
                        return

                    handler = threading.Thread(
                        target=serve_context_connection,
                        args=(downstream, upstream_path, packet),
                        name="ssh-agent-ctx-connection",
                    )
                    handlers.append(handler)
                    handler.start()

            acceptor = threading.Thread(
                target=accept_connections, name="ssh-agent-ctx-listener"
            )
            acceptor.start()

            try:
                return_code = process.wait()
            except KeyboardInterrupt:
                process.terminate()
                return_code = process.wait()
            finally:
                stop.set()
                listener.close()
                acceptor.join()
                for handler in handlers:
                    handler.join(timeout=2)

    return return_code


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a command with caller-provided SSH-agent context."
    )
    parser.add_argument(
        "--group-id",
        default=uuid.uuid4().hex,
        help="identifier shared by related signing requests (default: a new UUID)",
    )
    parser.add_argument(
        "--route",
        help="MacBook hostname or agent-witness (default: automatic)",
    )
    parser.add_argument("reason", help="why the command needs access to an SSH key")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    options = parser.parse_args(arguments)
    command = options.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required after the reason")

    upstream_path = os.environ.get("SSH_AUTH_SOCK")
    if not upstream_path:
        parser.error("SSH_AUTH_SOCK is not set")

    try:
        return run_with_context(
            RequestContext(
                options.group_id,
                options.reason,
                tuple(command),
                options.route,
            ),
            upstream_path,
        )
    except ProtocolError as error:
        parser.error(str(error))


def run() -> int:
    """Configure command-line logging and run the context wrapper."""

    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    return main()


if __name__ == "__main__":
    raise SystemExit(run())
