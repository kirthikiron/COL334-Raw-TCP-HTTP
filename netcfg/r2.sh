#!/bin/sh
set -e

IF_B="$1"
IF_C="$2"
IF_D="$3"

ip link set dev "$IF_B" up
ip link set dev "$IF_C" up
ip link set dev "$IF_D" up

ip addr flush dev "$IF_B"
ip addr flush dev "$IF_C"
ip addr flush dev "$IF_D"

ip addr add 10.10.2.2/24 dev "$IF_B"
ip addr add 10.10.3.1/24 dev "$IF_C"
ip addr add 10.10.4.1/30 dev "$IF_D"

# Router must forward packets (A4)
sysctl -qw net.ipv4.ip_forward=1

# Relax rp_filter on r2 due to asymmetric routing between IF_B and IF_D (A7)
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw "net.ipv4.conf.${IF_B}.rp_filter=0"
sysctl -qw "net.ipv4.conf.${IF_C}.rp_filter=0"
sysctl -qw "net.ipv4.conf.${IF_D}.rp_filter=0"

# Ensure no default route exists (A6)
ip route del default 2>/dev/null || true

# Return traffic to client goes over Link D (A3), rest of LAN A via r1 (A1)
ip route replace 10.10.1.10/32 via 10.10.4.2 dev "$IF_D"
ip route replace 10.10.1.0/24 via 10.10.2.1 dev "$IF_B"
