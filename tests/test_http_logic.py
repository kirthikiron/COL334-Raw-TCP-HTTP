"""Offline tests for the HTTP logic (no sockets). Run from the repo root:

    python tests/test_http_logic.py

Needs no mock and no raw sockets. Keep this folder out of the submission zip.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))
os.environ.setdefault("MOCK_TCP_DIR", os.path.join(HERE, ".."))  # any dir; stubbed below

# Stub the TCP layer so the modules import on any OS.
import types
stub = types.ModuleType("mock_tcp")
stub.RawTCPConnection = object
stub.RawTCPListener = object
sys.modules["mock_tcp"] = stub

import http_client as C   # noqa: E402
import http_server as S   # noqa: E402

fails = 0


def check(name, cond):
    global fails
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails += 1


# ---------------- client: URL parsing ----------------
check("url basic", C.parse_url("http://1.2.3.4/a/b") == ("1.2.3.4", 80, "/a/b", "1.2.3.4"))
check("url port+query", C.parse_url("http://h:8000/s?q=tcp") == ("h", 8000, "/s?q=tcp", "h:8000"))
check("url no path", C.parse_url("http://h")[2] == "/")
check("url query only", C.parse_url("http://h?x=1")[2] == "/?x=1")
check("url https rejected", C.parse_url("https://h/") is None)
check("url bad port", C.parse_url("http://h:99999/") is None)
check("url garbage", C.parse_url("hello") is None)

# ---------------- client: request ----------------
req = C.build_request("/p?q=1", "h:81").decode()
check("req line", req.startswith("GET /p?q=1 HTTP/1.1\r\n"))
check("req host", "Host: h:81\r\n" in req)
check("req close", "Connection: close\r\n" in req)
check("req no accept-encoding", "accept-encoding" not in req.lower())
check("req ends blank line", req.endswith("\r\n\r\n"))

# ---------------- client: response framing ----------------
r = C.parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
check("content-length ok", r[1] == 200 and r[2] == b"hello" and r[3])
r = C.parse_response(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nhello")
check("content-length short -> incomplete", not r[3])
r = C.parse_response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabc")
check("close-delimited", r[2] == b"abc" and r[3])
r = C.parse_response(
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n"
    b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nTrailer: x\r\n\r\n")
check("chunked ok", r[2] == b"Wikipedia" and r[3])
r = C.parse_response(
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npe")
check("chunked truncated -> incomplete", not r[3])
r = C.parse_response(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
check("404 parsed", r[1] == 404 and r[3])
r = C.parse_response(b"HTTP/1.1 200 OK\r\nContent-Le")
check("head truncated -> incomplete", not r[3])

# ---------------- server ----------------
root = tempfile.mkdtemp()
os.makedirs(os.path.join(root, "sub"))
os.makedirs(os.path.join(root, "empty"))
for name, data in [("index.html", b"<h1>root</h1>"), ("a.TXT", b"text"),
                   ("b.png", b"\x89PNG"), ("c.xyz", b"?"),
                   ("sub/index.html", b"sub")]:
    with open(os.path.join(root, name), "wb") as f:
        f.write(data)


def resp(line):
    out = S.handle_request(line.encode() + b"\r\nHost: x\r\n\r\n", root)
    head, _, body = out.partition(b"\r\n\r\n")
    return head.decode(), body


def status(line):
    return int(resp(line)[0].split()[1])


check("200 root", status("GET / HTTP/1.1") == 200)
check("200 index body", resp("GET / HTTP/1.1")[1] == b"<h1>root</h1>")
check("200 subdir (no slash)", resp("GET /sub HTTP/1.1")[1] == b"sub")
check("200 subdir slash", resp("GET /sub/ HTTP/1.1")[1] == b"sub")
check("query ignored", status("GET /?x=1 HTTP/1.1") == 200)
check("404 missing", status("GET /nope HTTP/1.1") == 404)
check("404 dir w/o index", status("GET /empty/ HTTP/1.1") == 404)
check("403 dotdot", status("GET /a/../b HTTP/1.1") == 403)
check("403 beats 404", status("GET /../x HTTP/1.1") == 403)
check("501 POST", status("POST / HTTP/1.1") == 501)
check("501 before 403", status("DELETE /../x HTTP/1.1") == 501)
check("400 no slash", status("GET x HTTP/1.1") == 400)
check("400 bad version", status("GET / HTTP/x") == 400)
check("400 missing parts", status("GET /") == 400)
check("400 extra space", status("GET /  HTTP/1.1") == 400)
check("400 before 501", status("POST x HTTP/1.1") == 400)
h, b = resp("HEAD / HTTP/1.1")
check("HEAD no body", b == b"" and "Content-Length: 13" in h)
h, b = resp("GET / HTTP/1.1")
check("headers present", all(k in h for k in
      ("Content-Length: 13", "Content-Type: text/html", "Connection: close")))
check("error has html body", b"<h1>" in resp("GET /nope HTTP/1.1")[1])
check("error content-length correct", "Content-Length: %d" % len(resp("GET /nope HTTP/1.1")[1])
      in resp("GET /nope HTTP/1.1")[0])
check("ctype case-insens", "text/plain" in resp("GET /a.TXT HTTP/1.1")[0])
check("ctype png", "image/png" in resp("GET /b.png HTTP/1.1")[0])
check("ctype default", "application/octet-stream" in resp("GET /c.xyz HTTP/1.1")[0])

print("\n%s (%d failure%s)" % ("ALL OK" if not fails else "PROBLEMS", fails, "" if fails == 1 else "s"))
sys.exit(1 if fails else 0)
