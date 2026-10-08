"""Pre-submission check + zip builder. Run from the repo root:

    python tools/package.py 2020CS10366 2020CS10367 --strip-mock

--strip-mock removes the "DEV ONLY" mock-import blocks from the copies of
http_client.py / http_server.py that go into the zip (your working files are
not changed). Without it, leftover mock code is reported as an error.

Checks for banned things, leftover mock code and missing files, then writes
A3_<entry1>_<entry2>.zip with the required layout. Keep tools/ and tests/ out
of the zip (this script already does).
"""
import os
import re
import sys
import zipfile

ROOT = os.getcwd()
INCLUDE_DIRS = ["netcfg", "client", "server", "src"]
INCLUDE_FILES = ["README.md", "report.pdf", "Makefile"]
REQUIRED = [
    "netcfg/client.sh", "netcfg/r1.sh", "netcfg/r2.sh", "netcfg/server.sh",
    "client/run-client", "server/run-server", "src", "README.md", "report.pdf",
]
EXEC = {"netcfg/client.sh", "netcfg/r1.sh", "netcfg/r2.sh", "netcfg/server.sh",
        "client/run-client", "server/run-server"}

# (regex, is_error). Errors = assignment says zero marks / leftover dev code.
CHECKS = [
    (r"SOCK_STREAM", True), (r"AF_PACKET", True),
    (r"\bscapy\b|\bdpkt\b|\blibpcap\b|\blibnet\b", True),
    (r"\bhttp\.client\b|\bhttp\.server\b|\burllib\b|\brequests\b|\bsocketserver\b|\basyncio\b", True),
    (r"\bsubprocess\b|\bos\.system\b|\bos\.popen\b|\bos\.exec\w*\b|\bpopen\(", True),
    (r"MOCK_TCP_DIR|mock_tcp", True),
    (r"\.listen\(|\bsocket\.accept\(", False),
    (r"IP_HDRINCL", None),  # must be present somewhere in src
]


DEV_RE = re.compile(r"# ---- DEV ONLY.*?# -+\nelse:\n    ", re.S)


def strip_dev(text):
    return DEV_RE.sub("", text)


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main():
    strip = "--strip-mock" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        print("usage: python tools/package.py ENTRY1 ENTRY2 [--strip-mock]")
        return 2
    entries = sorted(e.upper().replace("-", "").replace(" ", "") for e in args)
    out = "A3_%s_%s.zip" % tuple(entries)

    problems, warnings = [], []
    for r in REQUIRED:
        if not os.path.exists(os.path.join(ROOT, r)):
            problems.append("missing: " + r)

    hdrincl = False
    for dirpath, _, files in os.walk(os.path.join(ROOT, "src")):
        for fn in files:
            if fn.endswith(".pyc"):
                problems.append("binary in src: " + fn)
                continue
            if not fn.endswith((".py", ".c", ".cpp", ".h")):
                continue
            path = os.path.join(dirpath, fn)
            text = strip_dev(read(path)) if strip else read(path)
            for pat, kind in CHECKS:
                if kind is None:
                    hdrincl = hdrincl or re.search(pat, text) is not None
                    continue
                for i, line in enumerate(text.splitlines(), 1):
                    code = line.split("#", 1)[0]
                    if re.search(pat, code):
                        msg = "%s:%d: %s" % (os.path.relpath(path, ROOT), i, line.strip())
                        (problems if kind else warnings).append(msg)
    if not hdrincl:
        problems.append("IP_HDRINCL not found in src (raw sockets must build the IP header)")

    for r in ("client/run-client", "server/run-server"):
        p = os.path.join(ROOT, r)
        if os.path.exists(p) and "exec " not in read(p):
            problems.append(r + ": launcher must use exec")

    for w in warnings:
        print("WARN :", w)
    for p in problems:
        print("ERROR:", p)
    if problems:
        print("\nFix the errors above, then re-run. No zip written.")
        return 1

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        def add(rel):
            full = os.path.join(ROOT, rel)
            info = zipfile.ZipInfo(rel.replace(os.sep, "/"))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o755 if rel.replace(os.sep, "/") in EXEC else 0o644) << 16
            with open(full, "rb") as f:
                data = f.read()
            if rel.replace(os.sep, "/") in EXEC:      # force LF endings in scripts
                data = data.replace(b"\r\n", b"\n")
            if strip and rel.replace(os.sep, "/") in ("src/http_client.py", "src/http_server.py"):
                data = strip_dev(data.decode("utf-8")).encode("utf-8")
            z.writestr(info, data)

        for d in INCLUDE_DIRS:
            for dirpath, dirs, files in os.walk(os.path.join(ROOT, d)):
                dirs[:] = [x for x in dirs if x != "__pycache__"]
                for fn in sorted(files):
                    if fn.endswith(".pyc") or fn.endswith(".log"):
                        continue
                    add(os.path.relpath(os.path.join(dirpath, fn), ROOT))
        for fn in INCLUDE_FILES:
            if os.path.exists(os.path.join(ROOT, fn)):
                add(fn)

    print("Wrote", out)
    with zipfile.ZipFile(out) as z:
        for n in z.namelist():
            print("  ", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
