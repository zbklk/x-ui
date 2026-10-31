"""Loopback-only, bounded V2Ray Stats gRPC client; no proxy core CLI dependency.

Wire fields follow SagerNet/sing-box experimental/v2rayapi/stats.proto.
Counters are read without resetting, preserving the panel's durable delta logic.
"""
import socket
import struct
import time

import h2.config
import h2.connection
import h2.events
import h2.exceptions

LIMIT = 16 * 1024 * 1024


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            break
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise ValueError("Invalid protobuf varint")


def fields(data):
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        number, wire = key >> 3, key & 7
        if not number:
            raise ValueError("Invalid protobuf field")
        if wire == 0:
            value, offset = varint(data, offset)
        elif wire == 2:
            length, offset = varint(data, offset)
            if length > len(data) - offset:
                raise ValueError("Truncated protobuf field")
            value = data[offset:offset + length]
            offset += length
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            value = data[offset:offset + size]
            offset += size
            if len(value) != size:
                raise ValueError("Truncated protobuf field")
        else:
            raise ValueError("Unsupported protobuf wire type")
        yield number, wire, value


def decode_stats(body):
    if len(body) < 5 or body[0] != 0 or struct.unpack("!I", body[1:5])[0] != len(body) - 5:
        raise ValueError("Invalid gRPC message")
    stats = []
    for number, wire, entry in fields(body[5:]):
        if number != 1 or wire != 2:
            continue
        name, value = "", 0
        for field, kind, content in fields(entry):
            if field == 1 and kind == 2:
                name = content.decode("utf-8")
            elif field == 2 and kind == 0:
                if content >= 1 << 63:
                    raise ValueError("Negative traffic counter")
                value = content
        if name:
            stats.append({"name": name, "value": value})
        if len(stats) > 40000:
            raise ValueError("Too many counters")
    return stats


def query_stats(port, timeout=5):
    try:
        return _query_stats(port, timeout)
    except h2.exceptions.H2Error:
        raise ValueError("Invalid stats HTTP/2 response") from None


def _query_stats(port, timeout=5):
    request = b"\x1a\x07user>>>"  # QueryStatsRequest.patterns, reset=false.
    body = b"\x00" + struct.pack("!I", len(request)) + request
    client = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
    deadline = time.monotonic() + timeout
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as conn:
        client.initiate_connection()
        client.send_headers(1, [(":method", "POST"), (":scheme", "http"), (":authority", f"127.0.0.1:{port}"),
            (":path", "/v2ray.core.app.stats.command.StatsService/QueryStats"),
            ("content-type", "application/grpc"), ("te", "trailers"), ("grpc-timeout", "5S")])
        client.send_data(1, body, end_stream=True)
        conn.sendall(client.data_to_send())
        output, headers = bytearray(), {}
        while time.monotonic() < deadline:
            conn.settimeout(max(.01, deadline - time.monotonic()))
            chunk = conn.recv(65536)
            if not chunk:
                break
            for event in client.receive_data(chunk):
                if isinstance(event, (h2.events.ResponseReceived, h2.events.TrailersReceived)):
                    headers.update(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    output.extend(event.data)
                    if len(output) > LIMIT:
                        raise ValueError("Stats response too large")
                    client.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    if headers.get(":status") != "200" or headers.get("grpc-status") != "0":
                        raise ValueError("Stats RPC failed")
                    return decode_stats(output)
                elif isinstance(event, (h2.events.StreamReset, h2.events.ConnectionTerminated)):
                    raise ValueError("Stats connection reset")
            pending = client.data_to_send()
            if pending:
                conn.sendall(pending)
    raise ValueError("Stats response incomplete")
