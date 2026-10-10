#!/usr/bin/env python3
"""HTTP/1.1 GET client on top of our own raw TCP (Part C).

Usage: http_client.py URL [-o OUTFILE] [--log LOGFILE]
Exit codes: 0 = complete 2xx, 1 = complete non-2xx, 2 = anything else.
"""
import argparse
import contextlib
import os
import random
import re
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---- DEV ONLY (delete this block before submitting) -----------------------
# Set MOCK_TCP_DIR to the folder containing mock_tcp.py to test on Windows.
# if os.environ.get("MOCK_TCP_DIR"):
#     sys.path.insert(0, os.environ["MOCK_TCP_DIR"])
#     from mock_tcp import RawTCPConnection
# # ---------------------------------------------------------------------------
# else:
from raw_tcp import RawTCPConnection


# ------------------------------ pure helpers -------------------------------
URL_RE = re.compile(r"^http://([^/:?#\s]+)(?::(\d+))?([/?][^#\s]*)?$")


def parse_url(url):
    """Return (host, port, path, host_header) or None if invalid."""
    m = URL_RE.match(url)
    if not m:
        return None
    host, port_s, path = m.group(1), m.group(2), m.group(3)
    port = 80
    if port_s is not None:
        port = int(port_s)
        if not (1 <= port <= 65535):
            return None
    if not path:
        path = "/"
    elif path[0] == "?":
        path = "/" + path
    host_header = host + (":" + port_s if port_s is not None else "")
    return host, port, path, host_header


def build_request(path, host_header):
    return (
        "GET " + path + " HTTP/1.1\r\n"
        "Host: " + host_header + "\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii", errors="replace")


def decode_chunked(data):
    """Return (body, complete). Chunk extensions and trailers are ignored."""
    body = bytearray()
    pos = 0
    while True:
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            return bytes(body), False
        size_field = data[pos:eol].split(b";", 1)[0].strip()
        try:
            size = int(size_field, 16)
        except ValueError:
            return bytes(body), False
        pos = eol + 2
        if size == 0:
            return bytes(body), True  # trailers (if any) are ignored
        if len(data) < pos + size + 2:
            body += data[pos:pos + size]
            return bytes(body), False
        body += data[pos:pos + size]
        pos += size + 2


def parse_response(data):
    """Return (status_line, status_code, body, complete).

    status_line is None if the head never arrived."""
    sep = data.find(b"\r\n\r\n")
    if sep < 0:
        return None, None, b"", False
    head = data[:sep].decode("iso-8859-1")
    rest = data[sep + 4:]
    lines = head.split("\r\n")
    status_line = lines[0]
    parts = status_line.split(None, 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
        return status_line, None, b"", False
    code = int(parts[1])

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    if "chunked" in headers.get("transfer-encoding", "").lower():
        body, complete = decode_chunked(rest)
    elif "content-length" in headers:
        try:
            n = int(headers["content-length"])
        except ValueError:
            return status_line, code, rest, False
        body = rest[:n]
        complete = len(rest) >= n
    else:
        body, complete = rest, True  # body ends when server closes
    return status_line, code, body, complete


def resolve(host):
    """IPv4 literal -> itself; otherwise DNS. Raises OSError on failure."""
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        socket.inet_aton(host)
        return host
    return socket.gethostbyname(host)


def pick_source_ip(dst_ip):
    """Ask the routing table which local address would be used (no packet sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 9))
        return s.getsockname()[0]
    finally:
        s.close()


# --------------------------------- main ------------------------------------
def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("url")
    ap.add_argument("-o", dest="outfile")
    ap.add_argument("--log", dest="logfile")
    try:
        args = ap.parse_args(argv)
    except SystemExit:
        return 2

    parsed = parse_url(args.url)
    if parsed is None:
        print("invalid URL", file=sys.stderr)
        return 2
    host, port, path, host_header = parsed

    try:
        dst_ip = resolve(host)
        src_ip = pick_source_ip(dst_ip)
    except OSError as e:
        print("cannot resolve/route: %s" % e, file=sys.stderr)
        return 2

    src_port = random.randint(61000, 65535)
    data = b""
    try:
        # raw_tcp prints progress messages to stdout; keep stdout clean for the body
        with contextlib.redirect_stdout(sys.stderr):
            conn = RawTCPConnection(src_ip, dst_ip, port, src_port, args.logfile)
            if not conn.connect():
                return 2
            conn.send_all(build_request(path, host_header))
            data = conn.recv_all()
            conn.close()
    except (OSError, ConnectionError, TimeoutError) as e:
        print("connection error: %s" % e, file=sys.stderr)
        return 2

    status_line, code, body, complete = parse_response(data)
    if status_line is not None:
        print(status_line, file=sys.stderr)

    try:
        if args.outfile:
            with open(args.outfile, "wb") as f:
                f.write(body)
        else:
            sys.stdout.buffer.write(body)
            sys.stdout.buffer.flush()
    except OSError as e:
        print("cannot write output: %s" % e, file=sys.stderr)
        return 2

    if not complete or code is None:
        return 2
    return 0 if 200 <= code < 300 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))