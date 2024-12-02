# client
Uses a TUN adapter to receive packets from the OS, and sends it to the server. When packets are received back from the
server, they are written back to the TUN adapter.

To start the tun adapter:
```
bash client/scripts/tuntap.sh <user>
```

Then run the client.

To cleanup the adapter:
```
bash client/scripts/cleanup.sh
```

## Debugging:
Using wireshark to inspect packets:
```
wireshark -k -i TCP@127.0.0.1:19000
```