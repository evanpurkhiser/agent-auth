import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

SOURCE_PATH = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE_PATH))

from agent_proxy import (  # noqa: E402
    backends,
    config,
    diagnostics,
    notification,
    protocol,
    routing,
    service,
)
from agent_proxy import context as context_module  # noqa: E402


class RecordingBytesIO(io.BytesIO):
    def close(self) -> None:
        pass


def packet(message_type: int, body: bytes = b"") -> bytes:
    payload = bytes([message_type]) + body
    return len(payload).to_bytes(4, "big") + payload


class ConfigTests(unittest.TestCase):
    def test_missing_default_config_uses_defaults(self) -> None:
        with mock.patch.object(
            config, "DEFAULT_CONFIG_PATH", Path("/missing/agent-auth.toml")
        ):
            loaded = config.load_config(environment={})

        self.assertEqual(loaded.routing, config.RoutingConfig())

    def test_routing_config_is_loaded_from_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.toml")
            path.write_text(
                """
[routing]
computer_pattern = "workstation-.*"
ssh_key = "/run/keys/relay"
ssh_user = "relay"
agent_witness_socket = "/run/witness.sock"
"""
            )

            loaded = config.load_config(path, environment={})

        self.assertEqual(loaded.routing.computer_pattern, r"workstation-.*")
        self.assertEqual(loaded.routing.ssh_key, Path("/run/keys/relay"))
        self.assertEqual(loaded.routing.ssh_user, "relay")
        self.assertEqual(loaded.routing.agent_witness_socket, Path("/run/witness.sock"))

    def test_environment_overrides_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.toml")
            path.write_text('[routing]\nssh_user = "from-file"\n')

            loaded = config.load_config(
                path, environment={"AGENT_AUTH_SSH_USER": "from-environment"}
            )

        self.assertEqual(loaded.routing.ssh_user, "from-environment")

    def test_unknown_setting_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.toml")
            path.write_text('[routing]\nssh_host = "example"\n')

            with self.assertRaisesRegex(config.ConfigError, "ssh_host"):
                config.load_config(path, environment={})

    def test_invalid_computer_pattern_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.toml")
            path.write_text('[routing]\ncomputer_pattern = "["\n')

            with self.assertRaisesRegex(config.ConfigError, "computer_pattern"):
                config.load_config(path, environment={})

    def test_missing_explicit_config_is_rejected(self) -> None:
        with self.assertRaisesRegex(config.ConfigError, "does not exist"):
            config.load_config(Path("/missing/agent-auth.toml"), environment={})


class BackendTests(unittest.TestCase):
    def test_ssh_backend_opens_a_relay_connection(self) -> None:
        process = mock.Mock()
        process.stdin = RecordingBytesIO()
        process.stdout = RecordingBytesIO()
        routing_config = config.RoutingConfig(
            ssh_key=Path("/run/keys/relay"), ssh_user="relay"
        )
        backend = backends.SshAgentBackend("workstation", "100.64.0.2", routing_config)
        context = protocol.RequestContext("push-123", "Push changes", ("git", "push"))

        with mock.patch.object(
            backends.subprocess, "Popen", return_value=process
        ) as popen:
            connection = backend.connect(context)

        self.assertEqual(connection.reader, process.stdout)
        self.assertEqual(connection.writer, process.stdin)
        self.assertIs(connection.process, process)
        self.assertEqual(
            popen.call_args.args[0],
            [
                "ssh",
                "-T",
                "-i",
                "/run/keys/relay",
                "-l",
                "relay",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "100.64.0.2",
            ],
        )


class ContextProtocolTests(unittest.TestCase):
    def test_context_round_trip(self) -> None:
        context = protocol.RequestContext(
            "deployment-123",
            "Restart nginx after validating its configuration",
            ("sudo", "systemctl", "restart", "nginx"),
            "macbook-work",
        )

        encoded = protocol.encode_context(context)

        self.assertEqual(protocol.decode_context(encoded), context)
        self.assertEqual(protocol.extension_name(encoded), protocol.CONTEXT_EXTENSION)
        self.assertEqual(protocol.CONTEXT_EXTENSION, b"context@ssh-agent-auth")

    def test_invalid_context_is_rejected(self) -> None:
        contexts = (
            protocol.RequestContext("", "valid reason", ("ssh", "offsite")),
            protocol.RequestContext(
                "contains\na newline", "valid reason", ("ssh", "offsite")
            ),
            protocol.RequestContext("group-1", "", ("ssh", "offsite")),
            protocol.RequestContext(
                "group-1", "contains\na newline", ("ssh", "offsite")
            ),
            protocol.RequestContext("group-1", "valid reason", ()),
            protocol.RequestContext(
                "group-1", "valid reason", ("ssh", "offsite"), "bad\nroute"
            ),
        )

        for context in contexts:
            with self.subTest(context=context):
                with self.assertRaises(protocol.ProtocolError):
                    protocol.encode_context(context)

    def test_initial_context_is_acknowledged_and_consumed(self) -> None:
        context = protocol.RequestContext(
            "push-123", "Push reviewed changes", ("git", "push")
        )
        sign_request = packet(protocol.SSH_AGENTC_SIGN_REQUEST)
        reader = io.BytesIO(protocol.encode_context(context) + sign_request)
        writer = io.BytesIO()

        decoded, first_packet = protocol.read_initial_context(reader, writer)

        self.assertEqual(decoded, context)
        self.assertIsNone(first_packet)
        self.assertEqual(writer.getvalue(), protocol.SSH_AGENT_SUCCESS)
        self.assertEqual(protocol.read_packet(reader), sign_request)

    def test_ordinary_first_packet_is_retained(self) -> None:
        identity_request = packet(11)

        context, first_packet = protocol.read_initial_context(
            io.BytesIO(identity_request), io.BytesIO()
        )

        self.assertIsNone(context)
        self.assertEqual(first_packet, identity_request)


class RouteTests(unittest.TestCase):
    def test_ssh_options_are_formatted_from_keywords(self) -> None:
        self.assertEqual(
            backends.opt(ConnectTimeout=1),
            ["-o", "ConnectTimeout=1"],
        )

    def test_tailnet_name_is_shortened_to_hostname(self) -> None:
        self.assertEqual(
            routing.MacBookRoute("macbook-home.example.ts.net.", "100.64.0.1").hostname,
            "macbook-home",
        )

    def test_online_macbooks_are_ordered_by_last_handshake(self) -> None:
        status = {
            "Peer": {
                "old": {
                    "DNSName": "macbook-home.example.",
                    "Online": True,
                    "LastHandshake": "2026-09-01T10:00:00Z",
                    "TailscaleIPs": ["100.64.0.1"],
                },
                "new": {
                    "DNSName": "macbook-work.example.",
                    "Online": True,
                    "LastHandshake": "2026-09-02T10:00:00Z",
                    "TailscaleIPs": ["100.64.0.2"],
                },
                "offline": {
                    "DNSName": "macbook-away.example.",
                    "Online": False,
                    "LastHandshake": "2026-09-03T10:00:00Z",
                    "TailscaleIPs": ["100.64.0.3"],
                },
            }
        }

        routes = routing.parse_macbook_routes(status, r"macbook-.*")

        self.assertEqual(
            routes,
            [
                routing.MacBookRoute("macbook-work.example", "100.64.0.2"),
                routing.MacBookRoute("macbook-home.example", "100.64.0.1"),
            ],
        )

    def test_readiness_response_does_not_require_a_newline(self) -> None:
        status = json.dumps(
            {
                "Peer": {
                    "peer": {
                        "DNSName": "macbook-home.example.",
                        "Online": True,
                        "LastHandshake": "2026-09-02T10:00:00Z",
                        "TailscaleIPs": ["100.64.0.1"],
                    }
                }
            }
        ).encode()
        results = (
            subprocess.CompletedProcess([], 0, stdout=status),
            subprocess.CompletedProcess([], 0, stdout=b"ready"),
        )

        with mock.patch.object(routing.subprocess, "run", side_effect=results):
            backend = routing.find_ready_macbook()

        self.assertEqual(
            backend,
            backends.SshAgentBackend(
                "macbook-home", "100.64.0.1", config.RoutingConfig()
            ),
        )

    def test_requested_macbook_filters_candidates_by_hostname(self) -> None:
        status = json.dumps(
            {
                "Peer": {
                    "work": {
                        "DNSName": "macbook-work.example.",
                        "Online": True,
                        "LastHandshake": "2026-09-02T10:00:00Z",
                        "TailscaleIPs": ["100.64.0.2"],
                    },
                    "home": {
                        "DNSName": "macbook-home.example.",
                        "Online": True,
                        "LastHandshake": "2026-09-01T10:00:00Z",
                        "TailscaleIPs": ["100.64.0.1"],
                    },
                }
            }
        ).encode()
        results = (
            subprocess.CompletedProcess([], 0, stdout=status),
            subprocess.CompletedProcess([], 0, stdout=b"ready"),
        )

        with mock.patch.object(routing.subprocess, "run", side_effect=results) as run:
            backend = routing.find_ready_macbook("macbook-home")

        self.assertEqual(
            backend,
            backends.SshAgentBackend(
                "macbook-home", "100.64.0.1", config.RoutingConfig()
            ),
        )
        self.assertEqual(run.call_args_list[1].args[0][-1], "100.64.0.1")

    def test_configured_computer_pattern_filters_tailnet_peers(self) -> None:
        status = json.dumps(
            {
                "Peer": {
                    "macbook": {
                        "DNSName": "macbook-home.example.",
                        "Online": True,
                        "TailscaleIPs": ["100.64.0.1"],
                    },
                    "workstation": {
                        "DNSName": "workstation.example.",
                        "Online": True,
                        "TailscaleIPs": ["100.64.0.2"],
                    },
                }
            }
        ).encode()
        results = (
            subprocess.CompletedProcess([], 0, stdout=status),
            subprocess.CompletedProcess([], 0, stdout=b"ready"),
        )
        routing_config = config.RoutingConfig(computer_pattern=r"workstation\.")

        with mock.patch.object(routing.subprocess, "run", side_effect=results) as run:
            backend = routing.find_ready_macbook(config=routing_config)

        self.assertEqual(
            backend,
            backends.SshAgentBackend("workstation", "100.64.0.2", routing_config),
        )
        self.assertEqual(run.call_args_list[1].args[0][-1], "100.64.0.2")

    def test_requested_unavailable_route_does_not_fall_back(self) -> None:
        with (
            mock.patch.object(routing, "find_ready_macbook", return_value=None),
            self.assertRaisesRegex(RuntimeError, "macbook-away.*unavailable"),
        ):
            routing.select_backend("macbook-away")

    def test_agent_witness_can_be_selected_directly(self) -> None:
        with mock.patch.object(routing, "find_ready_macbook") as find_ready_macbook:
            result = routing.select_backend("agent-witness")

        self.assertEqual(result, backends.AgentWitnessBackend(config.RoutingConfig()))
        find_ready_macbook.assert_not_called()


class NotificationTests(unittest.TestCase):
    def test_notification_contains_reason_command_and_route(self) -> None:
        context = protocol.RequestContext(
            "push-123", "Update the remote branch", ("git", "push", "origin", "main")
        )
        response = mock.MagicMock()
        response.__enter__.return_value = response

        with (
            mock.patch.object(
                notification.socket, "gethostname", return_value="server"
            ),
            mock.patch.object(
                notification.urllib.request, "urlopen", return_value=response
            ) as urlopen,
        ):
            notification.send_notification(context, "macbook-home")

        request = urlopen.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, "https://bot.prk.network/")
        self.assertEqual(payload["parse_mode"], "MarkdownV2")
        self.assertEqual(
            payload["text"],
            "\n\n".join(
                (
                    "🔐 Update the remote branch",
                    "```command\ngit push origin main\n```",
                    r"\(agent\-auth from `server` via `macbook-home`\)",
                )
            ),
        )

    def test_markdown_escapes_reserved_characters(self) -> None:
        self.assertEqual(
            notification.escape_markdown(r"\_*[]()~`>#+-=|{}.!"),
            r"\\\_\*\[\]\(\)\~\`\>\#\+\-\=\|\{\}\.\!",
        )

    def test_code_escapes_backticks_and_backslashes(self) -> None:
        self.assertEqual(
            notification.escape_markdown("echo `pwd` \\\n--flag='[x]'", code=True),
            "echo \\`pwd\\` \\\\\n--flag='[x]'",
        )

    def test_connection_notifies_once_when_signing(self) -> None:
        sign_request = packet(protocol.SSH_AGENTC_SIGN_REQUEST)
        response = packet(14)
        backend_writer = RecordingBytesIO()
        client_writer = RecordingBytesIO()
        connection = backends.AgentConnection(io.BytesIO(response), backend_writer)
        backend = mock.Mock()
        backend.name = "agent-witness"
        backend.connect.return_value = connection
        context = protocol.RequestContext(
            "push-123", "Push changes", ("git", "push"), "agent-witness"
        )

        with (
            mock.patch.object(
                service, "select_backend", return_value=backend
            ) as select_backend,
            mock.patch.object(service, "send_notification") as notify,
        ):
            service.relay_agent_connection(
                io.BytesIO(
                    protocol.encode_context(context) + sign_request + sign_request
                ),
                client_writer,
            )

        select_backend.assert_called_once_with("agent-witness", None)
        backend.connect.assert_called_once_with(context)
        notify.assert_called_once_with(context, "agent-witness")
        self.assertEqual(backend_writer.getvalue(), sign_request + sign_request)
        self.assertEqual(
            client_writer.getvalue(), protocol.SSH_AGENT_SUCCESS + response
        )

    def test_empty_connection_is_rejected(self) -> None:
        with (
            mock.patch.object(service, "select_backend") as select_backend,
            self.assertRaisesRegex(
                protocol.ProtocolError, "closed before sending an SSH-agent packet"
            ),
        ):
            service.relay_agent_connection(io.BytesIO(), RecordingBytesIO())

        select_backend.assert_not_called()

    def test_missing_context_is_rejected_before_routing(self) -> None:
        identity_request = packet(11)
        client_writer = RecordingBytesIO()
        with (
            mock.patch.object(service, "select_backend") as select_backend,
            mock.patch.object(service, "warn_context_required") as warn,
            self.assertRaisesRegex(
                protocol.ContextRequiredError, "requires ssh-agent-ctx"
            ),
        ):
            service.relay_agent_connection(
                io.BytesIO(identity_request), client_writer, client_fd=42
            )

        self.assertEqual(client_writer.getvalue(), protocol.SSH_AGENT_FAILURE)
        select_backend.assert_not_called()
        warn.assert_called_once_with(42)

    def test_late_context_is_not_forwarded(self) -> None:
        initial_context = protocol.RequestContext(
            "ssh-123", "Connect to offsite", ("ssh", "offsite")
        )
        identity_request = packet(11)
        context_packet = protocol.encode_context(
            protocol.RequestContext("ssh-123", "Late context", ("ssh", "offsite"))
        )
        backend_writer = RecordingBytesIO()
        connection = backends.AgentConnection(io.BytesIO(), backend_writer)
        backend = mock.Mock()
        backend.name = "agent-witness"
        backend.connect.return_value = connection

        with (
            mock.patch.object(
                service, "select_backend", return_value=backend
            ) as select_backend,
            self.assertRaisesRegex(
                protocol.ProtocolError, "context must be the first packet"
            ),
        ):
            service.relay_agent_connection(
                io.BytesIO(
                    protocol.encode_context(initial_context)
                    + identity_request
                    + context_packet
                ),
                RecordingBytesIO(),
            )

        select_backend.assert_called_once_with(None, None)
        backend.connect.assert_called_once_with(initial_context)
        self.assertEqual(backend_writer.getvalue(), identity_request)


class DiagnosticsTests(unittest.TestCase):
    def test_context_warning_without_a_socket_is_ignored(self) -> None:
        with mock.patch.object(diagnostics, "peer_credentials") as peer_credentials:
            diagnostics.warn_context_required(None)

        peer_credentials.assert_not_called()

    def test_peer_credentials_come_from_the_connected_socket(self) -> None:
        left, right = socket.socketpair()
        with left, right:
            peer = diagnostics.peer_credentials(left.fileno())

        self.assertEqual(peer.pid, os.getpid())
        self.assertEqual(peer.uid, os.getuid())
        self.assertEqual(peer.gid, os.getgid())

    def test_context_warning_is_written_to_peer_stderr_tty(self) -> None:
        with (
            mock.patch.object(diagnostics.os, "readlink", return_value="/dev/pts/1"),
            mock.patch.object(diagnostics.os, "open", return_value=10),
            mock.patch.object(diagnostics.os, "isatty", return_value=True),
            mock.patch.object(diagnostics.os, "write") as write,
            mock.patch.object(diagnostics.os, "close") as close,
        ):
            result = diagnostics.write_peer_tty(123, "context required\n")

        self.assertTrue(result)
        write.assert_called_once_with(10, b"context required\n")
        close.assert_called_once_with(10)


class ContextRelayTests(unittest.TestCase):
    def test_wrapper_injects_context_before_relaying(self) -> None:
        request = packet(11)
        response = packet(12, b"ok")
        received_context: list[protocol.RequestContext] = []
        errors: list[Exception] = []

        with tempfile.TemporaryDirectory() as directory:
            upstream_path = str(Path(directory, "upstream.sock"))
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(upstream_path)
                listener.listen()

                def serve_upstream() -> None:
                    try:
                        connection, _ = listener.accept()
                        with connection:
                            stream = connection.makefile("rwb", buffering=0)
                            context_packet = protocol.read_packet(stream)
                            assert context_packet is not None
                            received_context.append(
                                protocol.decode_context(context_packet)
                            )
                            protocol.write_packet(stream, protocol.SSH_AGENT_SUCCESS)
                            self.assertEqual(protocol.read_packet(stream), request)
                            protocol.write_packet(stream, response)
                    except Exception as error:  # noqa: BLE001
                        errors.append(error)

                server = threading.Thread(target=serve_upstream, daemon=True)
                server.start()
                child = """
import os
import socket

request = bytes.fromhex('000000010b')
expected = bytes.fromhex('000000030c6f6b')
with socket.socket(socket.AF_UNIX) as client:
    client.connect(os.environ['SSH_AUTH_SOCK'])
    client.sendall(request)
    response = b''
    while len(response) < len(expected):
        response += client.recv(len(expected) - len(response))
    raise SystemExit(response != expected)
"""
                context = protocol.RequestContext(
                    "identities-123",
                    "List available identities",
                    (sys.executable, "-c", child),
                )

                return_code = context_module.run_with_context(context, upstream_path)
                server.join(timeout=2)

        self.assertEqual(return_code, 0)
        self.assertFalse(errors)
        self.assertEqual(received_context, [context])


class ContextCliTests(unittest.TestCase):
    def test_main_generates_a_group_id_for_the_wrapped_command(self) -> None:
        with (
            mock.patch.dict(
                context_module.os.environ, {"SSH_AUTH_SOCK": "/agent.sock"}
            ),
            mock.patch.object(
                context_module.uuid,
                "uuid4",
                return_value=mock.Mock(hex="generated-group-id"),
            ),
            mock.patch.object(
                context_module, "run_with_context", return_value=0
            ) as run_with_context,
        ):
            result = context_module.main(["Push changes", "--", "git", "push"])

        self.assertEqual(result, 0)
        run_with_context.assert_called_once_with(
            protocol.RequestContext(
                "generated-group-id", "Push changes", ("git", "push")
            ),
            "/agent.sock",
        )

    def test_main_uses_a_caller_provided_group_id(self) -> None:
        with (
            mock.patch.dict(
                context_module.os.environ, {"SSH_AUTH_SOCK": "/agent.sock"}
            ),
            mock.patch.object(context_module.uuid, "uuid4") as uuid4,
            mock.patch.object(
                context_module, "run_with_context", return_value=0
            ) as run_with_context,
        ):
            result = context_module.main(
                [
                    "--group-id",
                    "deployment-123",
                    "--route",
                    "agent-witness",
                    "Restart service",
                    "--",
                    "sudo",
                    "systemctl",
                    "restart",
                    "example",
                ]
            )

        self.assertEqual(result, 0)
        uuid4.assert_called_once_with()
        run_with_context.assert_called_once_with(
            protocol.RequestContext(
                "deployment-123",
                "Restart service",
                ("sudo", "systemctl", "restart", "example"),
                "agent-witness",
            ),
            "/agent.sock",
        )


class EntrypointTests(unittest.TestCase):
    def test_context_module_exposes_command_help(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(SOURCE_PATH)
        result = subprocess.run(
            [sys.executable, "-m", "agent_proxy.context", "--help"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("SSH-agent context", result.stdout)


if __name__ == "__main__":
    unittest.main()
