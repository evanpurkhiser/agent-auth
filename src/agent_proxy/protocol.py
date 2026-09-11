"""Define context data, validation, and strict SSH-agent packet encoding."""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO

CONTEXT_EXTENSION = b"context@ssh-agent-auth"
CONTEXT_VERSION = 1
SSH_AGENT_FAILURE = b"\x00\x00\x00\x01\x05"
SSH_AGENT_SUCCESS = b"\x00\x00\x00\x01\x06"
SSH_AGENTC_SIGN_REQUEST = 13
SSH_AGENTC_EXTENSION = 27

MAX_AGENT_PACKET_SIZE = 256 * 1024
MAX_GROUP_ID_SIZE = 128
MAX_ROUTE_SIZE = 253
MAX_REASON_SIZE = 512
MAX_COMMAND_ARGUMENTS = 128
MAX_COMMAND_SIZE = 16 * 1024


class ProtocolError(ValueError):
    """The peer sent an invalid or unsupported agent-proxy packet."""


class ContextRequiredError(ProtocolError):
    """The client attempted to use the SSH agent without request context."""


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Caller-provided explanation and the command launched under its scope."""

    group_id: str
    reason: str
    command: tuple[str, ...]
    route: str | None = None


@dataclass(slots=True)
class PacketDecoder:
    """Consume typed values from an SSH-agent packet without overrunning it."""

    data: memoryview
    offset: int = 0

    def take(self, size: int) -> bytes:
        """Consume exactly size bytes from the packet."""

        end = self.offset + size
        if end > len(self.data):
            raise ProtocolError("truncated context packet")

        value = bytes(self.data[self.offset : end])
        self.offset = end
        return value

    def take_u32(self) -> int:
        """Consume a network-byte-order unsigned 32-bit integer."""

        return struct.unpack(">I", self.take(4))[0]

    def take_string(self) -> bytes:
        """Consume an SSH length-prefixed byte string."""

        return self.take(self.take_u32())

    def finish(self) -> None:
        """Reject unconsumed data at the end of the packet."""

        if self.offset != len(self.data):
            raise ProtocolError("trailing context data")


def ssh_string(value: bytes) -> bytes:
    """Encode bytes as an SSH length-prefixed string."""

    return struct.pack(">I", len(value)) + value


def validate_context(context: RequestContext) -> None:
    """Validate context contents against protocol and resource limits."""

    group_id = context.group_id.encode("utf-8")
    if (
        not group_id
        or len(group_id) > MAX_GROUP_ID_SIZE
        or not context.group_id.isprintable()
    ):
        raise ProtocolError("group ID must be printable UTF-8 within the size limit")

    if context.route is not None:
        route = context.route.encode("utf-8")
        if not route or len(route) > MAX_ROUTE_SIZE or not context.route.isprintable():
            raise ProtocolError("route must be printable UTF-8 within the size limit")

    reason = context.reason.encode("utf-8")
    if not reason or len(reason) > MAX_REASON_SIZE or not context.reason.isprintable():
        raise ProtocolError("reason must be printable UTF-8 within the size limit")

    if not context.command or len(context.command) > MAX_COMMAND_ARGUMENTS:
        raise ProtocolError("command argument count is outside the allowed range")

    command_size = sum(len(os.fsencode(argument)) for argument in context.command)
    if command_size > MAX_COMMAND_SIZE:
        raise ProtocolError("command exceeds the size limit")


def encode_context(context: RequestContext) -> bytes:
    """Encode context as an SSH-agent extension packet."""

    validate_context(context)
    payload = bytearray([SSH_AGENTC_EXTENSION])
    payload.extend(ssh_string(CONTEXT_EXTENSION))
    payload.append(CONTEXT_VERSION)
    payload.extend(ssh_string(context.group_id.encode("utf-8")))
    payload.extend(ssh_string((context.route or "").encode("utf-8")))
    payload.extend(ssh_string(context.reason.encode("utf-8")))
    payload.extend(struct.pack(">I", len(context.command)))

    for argument in context.command:
        payload.extend(ssh_string(os.fsencode(argument)))

    return struct.pack(">I", len(payload)) + payload


def decode_context(packet: bytes) -> RequestContext:
    """Decode and strictly validate a context extension packet."""

    decoder = PacketDecoder(memoryview(packet))
    packet_length = decoder.take_u32()
    if packet_length != len(packet) - 4:
        raise ProtocolError("invalid packet length")
    if decoder.take(1) != bytes([SSH_AGENTC_EXTENSION]):
        raise ProtocolError("not an extension packet")
    if decoder.take_string() != CONTEXT_EXTENSION:
        raise ProtocolError("not an ssh-agent-auth context extension")
    if decoder.take(1) != bytes([CONTEXT_VERSION]):
        raise ProtocolError("unsupported context version")

    try:
        group_id = decoder.take_string().decode("utf-8")
        route = decoder.take_string().decode("utf-8") or None
        reason = decoder.take_string().decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProtocolError("context strings must be valid UTF-8") from error

    argument_count = decoder.take_u32()
    if argument_count > MAX_COMMAND_ARGUMENTS:
        raise ProtocolError("too many command arguments")

    command = tuple(
        decoder.take_string().decode("utf-8", errors="replace")
        for _ in range(argument_count)
    )
    decoder.finish()

    context = RequestContext(group_id, reason, command, route)
    validate_context(context)
    return context


def read_exact(stream: BinaryIO, size: int) -> bytes:
    """Read exactly size bytes or raise when the stream closes early."""

    data = bytearray()
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError("connection closed during an SSH-agent packet")
        data.extend(chunk)
    return bytes(data)


def read_packet(stream: BinaryIO) -> bytes | None:
    """Read one bounded SSH-agent packet, returning None at clean EOF."""

    header = stream.read(4)
    if not header:
        return None
    if len(header) < 4:
        header += read_exact(stream, 4 - len(header))

    size = struct.unpack(">I", header)[0]
    if not 0 < size <= MAX_AGENT_PACKET_SIZE:
        raise ProtocolError("invalid SSH-agent packet size")
    return header + read_exact(stream, size)


def write_packet(stream: BinaryIO, packet: bytes) -> None:
    """Write and flush one complete SSH-agent packet."""

    stream.write(packet)
    stream.flush()


def extension_name(packet: bytes) -> bytes | None:
    """Return an extension packet's name, or None for other packets."""

    if len(packet) < 9 or packet[4] != SSH_AGENTC_EXTENSION:
        return None

    decoder = PacketDecoder(memoryview(packet)[5:])
    try:
        return decoder.take_string()
    except ProtocolError:
        return None


def is_sign_request(packet: bytes) -> bool:
    """Return whether a packet requests an SSH signature."""

    return len(packet) >= 5 and packet[4] == SSH_AGENTC_SIGN_REQUEST


def read_initial_context(
    reader: BinaryIO, writer: BinaryIO
) -> tuple[RequestContext | None, bytes | None]:
    """Consume an optional context extension and retain an ordinary first packet."""

    packet = read_packet(reader)
    if packet is None or extension_name(packet) != CONTEXT_EXTENSION:
        return None, packet

    try:
        context = decode_context(packet)
    except ProtocolError:
        write_packet(writer, SSH_AGENT_FAILURE)
        raise

    write_packet(writer, SSH_AGENT_SUCCESS)
    return context, None
