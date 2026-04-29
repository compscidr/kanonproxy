# kanonproxy
[![JVM Tests](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml/badge.svg)](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml)&nbsp;
[![codecov](https://codecov.io/gh/compscidr/kanonproxy/graph/badge.svg?token=yBstrWw9Mm)](https://codecov.io/gh/compscidr/kanonproxy)&nbsp;

An anonymous proxy written in kotlin.

For a deeper architectural overview of how the modules and external libraries fit together,
see [docs/architecture.md](docs/architecture.md).

## Demo videos

Two short clips of the Android sample app in action (click to play on YouTube):

| Android demo | Android demo with Wireshark |
|:---:|:---:|
| [![Android demo](https://img.youtube.com/vi/wlaYF5m-GBo/maxresdefault.jpg)](https://youtu.be/wlaYF5m-GBo) | [![Android demo with Wireshark](https://img.youtube.com/vi/zhUrEmBCZSM/maxresdefault.jpg)](https://youtu.be/zhUrEmBCZSM) |
| The `android` module running as a VPN service and proxying traffic on a real device. | The same app with Wireshark attached to the in-app `PcapNgTcpServerPacketDumper`, watching packets go through the proxy live. |

## Modules

There are four modules in this project:

### `core`
The core module is meant to be a library that can run on Android or Linux. It does not
provide the client / server functionality. It is able to process packets which have
been parsed by https://github.com/compscidr/knet, manage sessions and make outgoing
anonymous requests based on the incoming traffic. It also receives the return traffic,
and puts them into a queue. Outgoing ICMP requests are made by https://github.com/compscidr/icmp.

It is up to consumers of this library to implement a server, a tun/tap adapter, or a
VPN service on Android to make use of it.

### `server`
A reference UDP-based proxy server (`ProxyServer`) built on top of `core`. It listens on
a `DatagramChannel`, parses inbound packets with knet, dispatches them to `KAnonProxy`,
and returns responses back to the originating client. Run it directly via
`ProxyServer.main` (defaults to port `8080`).

### `client`
A reference client (`ProxyClient`) that reads/writes a TUN adapter and tunnels the
parsed packets over UDP to a `ProxyServer`. `LinuxProxyClient` is the Linux entry point;
helper scripts to set up and tear down the TUN device live in [`client/scripts/`](client/scripts).
See [`client/README.md`](client/README.md) for setup details.

### `android`
A sample Android app (`KAnonVpnService` + `MainActivity`) that uses Android's `VpnService`
to intercept packets. It runs both `ProxyServer` and `AndroidClient` in-process, wired to
`IcmpAndroid` for ICMP support.

## Usage
The examples below show a contrived example where the packets are manually constructed. This
is a valid usecase, however, you probably want instead to parse a stream from an OS via a
TUN/TAP driver, or an Android VPN iostream or something. This library takes a list of 
the `Packet` type from the knet library https://github.com/compscidr/knet, so if you have a
stream, you can convert that stream into a list of packets by parsing it with that lib.

The other thing to note is that in order to handle Icmp traffic, we use the icmp library:
https://github.com/compscidr/icmp. Depending on whether you are on linux or android, you
should pass the appropriate `Icmp` object to the proxy. On linux its `IcmpLinux` on android
its `IcmpAndroid`. You also need to use different dependencies for each. For linux
`implementation("com.jasonernst.icmp:icmp-linux")` and for android 
`implementation("com.jasonernst.icmp:icmp-android")`

Linux:
```kotlin
val kanonProxy = KAnonProxy(IcmpLinux)

val payload = "Test Data".toByteArray()
val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
val sourcePort: UShort = 12345u
val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
val destinationPort: UShort = 54321u
val udpHeader = UdpHeader(sourcePort, destinationPort, payload.size.toUShort())
val packet =
    Packet(
        Ipv4Header(
            sourceAddress = sourceAddress,
            destinationAddress = destinationAddress,
            protocol = IpType.UDP.value,
            totalLength =
            (
                    Ipv4Header.IP4_MIN_HEADER_LENGTH +
                            udpHeader.totalLength +
                            payload.size.toUShort()
                    ).toUShort(),
        ),
        udpHeader,
        payload,
    )
val packets = listOf(packet)
kAnonProxy.handlePackets(packets)
val response = kanonProxy.takeResponse()
```

There are more examples of usage in the [tests](core/src/test/kotlin/com/jasonernst/kanonproxy).

## Local Linux demo

A scripted end-to-end demo that brings up the server, the client, and tunnels a
single curl request through the proxy.

Prerequisites:
- Linux with `iproute2` and `sudo` (the script creates a TUN device and adds a
  route — both require root)
- JDK 21 (the wrapper handles Gradle itself)

One-shot:
```bash
bash client/scripts/demo.sh           # uses 1.1.1.1 as the curl target
bash client/scripts/demo.sh 9.9.9.9   # or pick your own HTTP-reachable IP
```

The script will:
1. Run `client/scripts/tuntap.sh` to create the `kanon` TUN device
   (`10.0.1.1/24`, MTU 1024).
2. Start the proxy server with `./gradlew :server:run --args="8080"` (UDP
   listener on port 8080) — logs to `build/demo-logs/server.log`.
3. Start the proxy client with `./gradlew :client:run --args="127.0.0.1 8080"` —
   logs to `build/demo-logs/client.log`.
4. Add a host route for the target IP through the `kanon` device so the kernel
   sends matching packets through the TUN, where the client picks them up.
5. Run `curl -v http://<target>/` and print the response.

Tear-down:
```bash
bash client/scripts/cleanup.sh
```
This kills the server/client/Gradle workers, drops every route bound to the
`kanon` device, and removes the TUN interface.

### Step-by-step (without the script)

If you want to run it by hand to see what each piece does:

```bash
# Terminal 1 — TUN device
bash client/scripts/tuntap.sh "$USER"

# Terminal 2 — server (UDP :8080)
./gradlew :server:run --args="8080"

# Terminal 3 — client (TUN ↔ UDP to 127.0.0.1:8080)
./gradlew :client:run --args="127.0.0.1 8080"

# Terminal 4 — route a target through kanon and curl it
sudo ip route add 1.1.1.1 dev kanon
curl -v http://1.1.1.1/

# Cleanup
sudo ip route del 1.1.1.1 dev kanon
bash client/scripts/cleanup.sh
```

While the demo is running you can attach Wireshark to either side's pcap-ng
stream — see [Debugging with Wireshark](#debugging-with-wireshark) below.

## Debugging with Wireshark

Both the reference server/client and the Android sample app embed a
[`PcapNgTcpServerPacketDumper`](https://github.com/compscidr/packetdumper) that can
expose a live pcap-ng stream over TCP. Wireshark attaches to it directly, no PCAP
files on disk:

```bash
wireshark -k -i TCP@<host>:<port>
```

`-k` starts capture immediately; `-i TCP@host:port` is Wireshark's pcap-ng-over-TCP
source. The host and port depend on where the dumper is running:

- **`LinuxProxyClient`** — listens on `PcapNgTcpServerPacketDumper.DEFAULT_PORT`
  (`19000`) on localhost:
  ```bash
  wireshark -k -i TCP@127.0.0.1:19000
  ```

- **`ProxyServer.main`** — listens on `PcapNgTcpServerPacketDumper.DEFAULT_PORT + 1`
  (`19001`) on localhost, to avoid clashing with a co-located client:
  ```bash
  wireshark -k -i TCP@127.0.0.1:19001
  ```

- **Android sample app** — the dumper is *not* started with the VPN; you have to
  enable it from the app's UI (the Wireshark/pcap-server toggle, which calls
  `startPcapServer()`). Once enabled it listens on the phone's Wi-Fi interface, so
  `127.0.0.1` will not work from your computer. Use the **phone's Wi-Fi IP**, and
  make sure the phone and the computer running Wireshark are on the **same subnet**
  (and that no AP isolation / firewall blocks port `19000`):
  ```bash
  wireshark -k -i TCP@<phone-wifi-ip>:19000   # e.g. TCP@192.168.1.42:19000
  ```
  You can find the phone's Wi-Fi IP under Settings → About phone → Status, or
  inside the sample app's UI.
