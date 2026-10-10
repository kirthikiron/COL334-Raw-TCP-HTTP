# COL334 Assignment 3: Raw TCP/IPv4 and HTTP

## Team Members

- Peduru Kirthi Kiron : 2020CS10366
- Pragya Malaiya : 2020CS10367

## Overview

- Language: Python 3 (standard library only)
- Environment: Ubuntu 22.04 LTS on QEMU / KVM
- Build: No build or compilation step is needed. The project uses raw sockets (`AF_INET`, `SOCK_RAW`), so everything must be run as root (`sudo`).

## Repository Structure

- `netcfg/` — network scripts for the 4 VMs (`client.sh`, `r1.sh`, `r2.sh`, `server.sh`)
- `src/raw_tcp.py` — IPv4 and TCP stack over raw sockets (checksums, packet crafting, Reno congestion control, out-of-order buffering, monotonic ACKs)
- `src/http_client.py` — HTTP client (GET, chunked decoding, Content-Length)
- `src/http_server.py` — static HTTP server (GET and HEAD)
- `client/run-client` — client launcher
- `server/run-server` — server launcher
- `report.pdf` — report with screenshots and explanations for R1 to R6

## VM and Environment Setup (Required)

Before running the client or server, run the following on the VMs so raw sockets work under QEMU.

### 1. Network config (Part A)

Run the matching script as root on each VM, passing its interface names:

- client: `sudo ./netcfg/client.sh <IF_A> <IF_D>`
- r1: `sudo ./netcfg/r1.sh <IF_A> <IF_B>`
- r2: `sudo ./netcfg/r2.sh <IF_B> <IF_C> <IF_D>`
- server: `sudo ./netcfg/server.sh <IF_C>`

`client.sh` and `r2.sh` set `rp_filter=0` because of asymmetric routing. `r1.sh` and `server.sh` leave `rp_filter=1`.

### 2. Kernel RST suppression

The Linux kernel does not know about our raw-socket connections and will send RST packets that kill them. Run this on both the client and the server VM:

```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

### 3. Checksum and packet-coalescing offloads

In QEMU/KVM the virtual NIC has GRO and checksum offload on by default. Burst packets are then merged and handed to the raw socket with a placeholder checksum, which our code drops as corrupt.

Disable the offloads on the active interfaces of the client and server VMs:

```bash
# On the client VM:
sudo ethtool -K <IF_A> rx off tx off gro off gso off
sudo ethtool -K <IF_D> rx off tx off gro off gso off

# On the server VM:
sudo ethtool -K <IF_C> rx off tx off gro off gso off
```

## How to Run

### HTTP client (Part C)

```bash
sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]
```

- Exit code 0: completed with a 2xx status
- Exit code 1: completed with a non-2xx status (404, 403, 501, ...)
- Exit code 2: connection error, timeout, bad URL, or truncated response

Example:

```bash
sudo ./client/run-client http://10.10.3.10:8080/index.html -o index.html
```

### HTTP server (Part D)

```bash
sudo ./server/run-server [-p PORT] [-d DOCROOT] [--log LOGFILE]
```

Defaults: port 8080, docroot `./www`.

Example:

```bash
sudo ./server/run-server -p 8080 -d ~/www
```
