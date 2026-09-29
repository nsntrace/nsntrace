#!/bin/sh
# Send to the gateway, not 127.0.0.1: with lo up, loopback traffic
# never crosses the veth nsntrace actually captures on.
gw=$(ip route show default | awk '{print $3}')
exec ./udp_send 1337 "$1" 0 "$gw"
