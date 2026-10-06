#!/bin/sh
set -e

IF_A="$1"
IF_D="$2"

ip link set dev "$IF_A" up
ip link set dev "$IF_D" up

ip addr flush dev "$IF_A"
ip addr flush dev "$IF_D"

ip addr add 10.10.1.10/24 dev "$IF_A"
ip addr add 10.10.4.2/30 dev "$IF_D"

# Host must not forward packets (A4)
sysctl -qw net.ipv4.ip_forward=0

# Relax rp_filter for asymmetric return over Link D (A3, A7)
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0
sysctl -qw "net.ipv4.conf.${IF_A}.rp_filter=0"
sysctl -qw "net.ipv4.conf.${IF_D}.rp_filter=0"

# Forward path to LAN B and LAN C goes via r1 (A1, A2)
ip route replace 10.10.2.0/24 via 10.10.1.1 dev "$IF_A"
ip route replace 10.10.3.0/24 via 10.10.1.1 dev "$IF_A"
