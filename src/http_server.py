#!/usr/bin/env python3
"""HTTP/1.1 static file server on top of our own raw TCP (Part D).

Usage: http_server.py [-p PORT] [-d DOCROOT] [--log LOGFILE]
"""
import argparse
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ---- DEV ONLY (delete this block before submitting) -----------------------
# if os.environ.get("MOCK_TCP_DIR"):
#     sys.path.insert(0, os.environ["MOCK_TCP_DIR"])
#     from mock_tcp import RawTCPListener
# # ---------------------------------------------------------------------------
# else:
from raw_tcp import RawTCPListener

HEAD_TIMEOUT = 10.0
MAX_HEAD = 65536

CONTENT_TYPES = {
    ".html": "text/html", ".htm": "text/html",
    ".txt": "text/plain",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".pdf": "application/pdf",
}
REASONS = {
    200: "OK", 400: "Bad Request", 403: "Forbidden",
    404: "Not Found", 501: "Not Implemented",
}
REQ_LINE_RE = re.compile(r"^([^ ]+) ([^ ]+) HTTP/\d+\.\d+$")


# ------------------------------ pure helpers -------------------------------
def content_type_for(path):
    ext = os.path.splitext(path)[1].lower()
    return CONTENT_TYPES.get(ext, "application/octet-stream")


def build_response(status, ctype, body, head_only=False):
    head = (
        "HTTP/1.1 %d %s\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: %s\r\n"
        "Connection: close\r\n"
        "\r\n" % (status, REASONS[status], len(body), ctype)
    ).encode("ascii")
    return head if head_only else head + body


def error_response(status, head_only=False):
    msg = "%d %s" % (status, REASONS[status])
    body = ("<html><head><title>%s</title></head>"
            "<body><h1>%s</h1></body></html>" % (msg, msg)).encode("ascii")
    return build_response(status, "text/html", body, head_only)


def handle_request(head_bytes, docroot):
    """Table 4, checked in order. Returns the full response bytes."""
    try:
        line = head_bytes.split(b"\r\n", 1)[0].decode("iso-8859-1")
    except Exception:
        return error_response(400)

    m = REQ_LINE_RE.match(line)                       # 1. malformed
    if not m or not m.group(2).startswith("/"):
        return error_response(400)
    method, target = m.group(1), m.group(2)

    if method not in ("GET", "HEAD"):                 # 2. method
        return error_response(501)
    head_only = (method == "HEAD")

    path = target.split("?", 1)[0]                    # strip query string
    segments = path.split("/")
    if ".." in segments:                              # 3. traversal
        return error_response(403, head_only)

    fs_path = os.path.join(docroot, path.lstrip("/"))
    if path.endswith("/") or os.path.isdir(fs_path):
        fs_path = os.path.join(fs_path, "index.html")

    if not os.path.isfile(fs_path):                   # 4. missing
        return error_response(404, head_only)

    try:
        with open(fs_path, "rb") as f:
            body = f.read()
    except OSError:
        return error_response(404, head_only)

    return build_response(200, content_type_for(fs_path), body, head_only)  # 5.


# ------------------------------ connection I/O -----------------------------
def read_request_head(conn):
    """Read until CRLFCRLF. Returns bytes, or None if incomplete in 10 s."""
    deadline = time.time() + HEAD_TIMEOUT
    buf = b""
    while b"\r\n\r\n" not in buf:
        remaining = deadline - time.time()
        if remaining <= 0 or len(buf) > MAX_HEAD:
            return None
        chunk = conn.recv_some(remaining)  # needs Partner A's recv_some()
        if chunk is None:                  # timeout slice, keep waiting
            continue
        if chunk == b"":                   # peer closed before head complete
            return None
        buf += chunk
    return buf


def serve_one(conn, docroot):
    try:
        head = read_request_head(conn)
        if head is not None:
            conn.send_all(handle_request(head, docroot))
        conn.close()
    except Exception:
        try:
            conn.sock.close()      # don't leak the raw socket on a bad client
        except Exception:
            pass
        raise


def main(argv):
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("-p", dest="port", type=int, default=8080)
    ap.add_argument("-d", dest="docroot", default="./www")
    ap.add_argument("--log", dest="logfile")
    args = ap.parse_args(argv)

    listener = RawTCPListener("0.0.0.0", args.port, args.logfile)

    while True:                                       # runs until killed
        try:
            conn = listener.accept()
            serve_one(conn, args.docroot)
        except KeyboardInterrupt:
            break
        except Exception as e:                        # never die on a bad client
            print("connection error: %s" % e, file=sys.stderr)
            continue


if __name__ == "__main__":
    main(sys.argv[1:])