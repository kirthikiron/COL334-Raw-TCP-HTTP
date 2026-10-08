# COL334 Assignment 3: Raw TCP/IPv4 and HTTP

## Team Members
- Member 1: 2020CS10366
- Member 2: 2020CS10367

## Language and Runtime
- Language: Python 3, standard library only
- Runtime: Python 3.10 on Ubuntu 22.04 (x86-64)

## How to Build
No build step is needed. There is no Makefile. Run everything as root
(raw sockets need it).

## Layout
- `netcfg/` : one configuration script per VM (Part A)
- `src/raw_tcp.py` : IPv4/TCP over raw sockets, packet log (Part B)
- `src/http_client.py` : HTTP client (Part C)
- `src/http_server.py` : HTTP server (Part D)
- `client/run-client`, `server/run-server` : launchers

## Running

### Network configuration (Part A)
Run as root on each VM, passing interface names:
- client: `sudo ./netcfg/client.sh IF_A IF_D`
- r1: `sudo ./netcfg/r1.sh IF_A IF_B`
- r2: `sudo ./netcfg/r2.sh IF_B IF_C IF_D`
- server: `sudo ./netcfg/server.sh IF_C`

### Kernel RST suppression
Because the kernel has no socket for our connections, it answers incoming
segments with RST. On the client and server VMs, run before using the
programs:

    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP

### HTTP client (Part C)
    sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]
Exit code 0 = complete 2xx response, 1 = complete non-2xx response, 2 = anything else.

### HTTP server (Part D)
    sudo ./server/run-server [-p PORT] [-d DOCROOT] [--log LOGFILE]
Defaults: port 8080, docroot `./www`.
