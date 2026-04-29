#!/bin/bash
# Kill kanonproxy processes (java -jar, gradle-launched mains, the gradle
# daemon), drop any routes pointed at the kanon device, and delete the
# kanon TUN interface.
sudo pkill -f "java -jar"
sudo pkill -f "java -Djava.library.path"
sudo pkill -f "ProxyServer"
sudo pkill -f "LinuxProxyClient"
sudo pkill -f "GradleWorkerMain"
{
  # drop any host routes pointed at kanon (added by demo.sh)
  ip route show | awk '/dev kanon/ {print $1}' | while read -r net; do
    sudo ip route del "$net" dev kanon
  done

  # try to cleanup old interfaces first
  # hide output of these - we'll get a failure message if the kanon interface doesn't exist
  # and we don't care if it doesn't
  sudo ip link set dev kanon down
  sudo ip tuntap del dev kanon mode tun
  rm *.jar *.so
} &> /dev/null