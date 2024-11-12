#!/bin/bash
# usage: ./tun-tap <USERNAME>
if [ -z "$1" ]; then
    echo "usage:  ./tun-tap <USERNAME>"
    exit 22
fi
{
  # try to cleanup old interfaces first
  # hide output of these - we'll get a failure message if the kanon interface doesn't exist
  # and we don't care if it doesn't
  sudo ip link set dev kanon down
  sudo ip tuntap del dev kanon mode tun
} &> /dev/null

# exit when any command fails
set -e

sudo ip tuntap add dev kanon mode tun user $1 group $1
sudo ip addr add 10.0.1.1/24 dev kanon
sudo ip link set dev kanon up mtu 1024