#!/bin/sh
set -e

IF_C="$1"

ip link set dev "$IF_C" up
ip addr flush dev "$IF_C"
ip addr add 10.10.3.10/24 dev "$IF_C"

# Host must not forward packets (A4)
sysctl -qw net.ipv4.ip_forward=0

# Keep strict rp_filter=1 on server (A7)
sysctl -qw net.ipv4.conf.all.rp_filter=1
sysctl -qw net.ipv4.conf.default.rp_filter=1
sysctl -qw "net.ipv4.conf.${IF_C}.rp_filter=1"

# Route all other networks via r2 (A1, A3)
ip route replace default via 10.10.3.1 dev "$IF_C"
