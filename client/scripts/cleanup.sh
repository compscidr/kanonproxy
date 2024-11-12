#!/bin/bash
# Kill and java -jar invoked processes, delete kanon namespace, delete kanon interface
sudo pkill -f "java -jar"
sudo pkill -f "java -Djava.library.path"
{
  # try to cleanup old interfaces first
  # hide output of these - we'll get a failure message if the bump interface doesn't exist
  # and we don't care if it doesn't
  sudo ip link set dev kanon down
  sudo ip tuntap del dev kanon mode tun
  rm *.jar *.so
} &> /dev/null