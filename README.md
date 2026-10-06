# COL334 Assignment 3: Raw TCP/IPv4 and HTTP

## Team Members
- Member 1: 2020CS10366
- Member 2: 2020CS10367

## Language and Runtime
- Language: Python 3 (Standard Library only)
- Runtime: Python 3.10 on Ubuntu 22.04 (x86-64)

## How to Build and Run
No compilation is required.

### Network Configuration (Part A)
Run as root on each respective VM:
- Client: `sudo ./netcfg/client.sh <IF_A> <IF_D>`
- Router 1: `sudo ./netcfg/r1.sh <IF_A> <IF_B>`
- Router 2: `sudo ./netcfg/r2.sh <IF_B> <IF_C> <IF_D>`
- Server: `sudo ./netcfg/server.sh <IF_C>`

### HTTP Client (Part C)
`sudo ./client/run-client URL [-o OUTFILE] [--log LOGFILE]`

### HTTP Server (Part D)
`sudo ./server/run-server [-p PORT] [-d DOCROOT] [--log LOGFILE]`
