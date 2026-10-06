#!/bin/sh
set -e

IF_A="$1"
IF_B="$2"

ip link set dev "$IF_A" up
ip link set dev "$IF_B" up

ip addr flush dev "$IF_A"
ip addr flush dev "$IF_B"

ip addr add 10.10.1.1/24 dev "$IF_A"
ip addr add 10.10.2.1/24 dev "$IF_B"

# Router must forward packets (A4)
sysctl -qw net.ipv4.ip_forward=1

# Keep strict rp_filter=1 on r1 (A7)
sysctl -qw net.ipv4.conf.all.rp_filter=1
sysctl -qw net.ipv4.conf.default.rp_filter=1
sysctl -qw "net.ipv4.conf.${IF_A}.rp_filter=1"
sysctl -qw "net.ipv4.conf.${IF_B}.rp_filter=1"

# Single route to reach all non-connected networks (A5)
ip route replace 10.10.0.0/16 via 10.10.2.2 dev "$IF_B"
