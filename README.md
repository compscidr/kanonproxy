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

An end-to-end demo on a single Linux host: a kanonproxy server, a kanonproxy
client tunneling a TUN device to that server, and a `curl` issued through the
proxy.

[![Local Linux demo](https://img.youtube.com/vi/_ypo_3PYqTM/maxresdefault.jpg)](https://youtu.be/_ypo_3PYqTM)

(Click to watch on YouTube — the steps below produce what the video shows.)

Prerequisites:
- Linux with `iproute2` and `sudo` (TUN setup and `--interface` both need root)
- JDK 21 (the Gradle wrapper handles Gradle itself)
- `./gradlew :server:assemble :client:assemble` succeeds

### Path A — scripted (one-shot)

```bash
bash client/scripts/demo.sh           # uses 1.1.1.1 as the curl target
bash client/scripts/demo.sh 9.9.9.9   # or pick your own HTTP-reachable IP
```

The script will:
1. Run `client/scripts/tuntap.sh` to create the persistent `kanon` TUN device
   (`10.0.1.1/24`, MTU 1024).
2. Start the proxy server with `./gradlew :server:run --args="8080"` (UDP
   listener on port 8080) — logs to `build/demo-logs/server.log`.
3. Start the proxy client with `./gradlew :client:run --args="127.0.0.1 8080"` —
   logs to `build/demo-logs/client.log`.
4. Run `sudo curl -v --interface kanon http://<target>/`. `--interface kanon`
   uses `SO_BINDTODEVICE` to pin curl's socket to the TUN, so curl's packets
   go into the proxy without touching the kernel's main route table. The
   server's own outbound TCP socket stays unbound and follows the normal
   default route — that's what prevents the server from looping back into
   its own VPN.

The server and client stay running after the script finishes, so you can fire
more requests against the same proxy:
```bash
sudo curl -v --interface kanon http://example.com/
sudo curl -v --interface kanon http://1.1.1.1/
```
Each call creates a new session — look for `New session: ...` lines in
`tail -f build/demo-logs/server.log`.

Tear-down:
```bash
bash client/scripts/cleanup.sh
```
This SIGTERMs the server/client/Gradle workers (then SIGKILLs anything left),
retries `ip tuntap del` to handle any fd-release race, and removes the TUN
interface. It's idempotent — safe to rerun.

### Path B — manual (4 terminals)

Use this if you want to see each piece's output live, or to debug a failure
from path A.

**Terminal 1 — TUN device:**
```bash
bash client/scripts/tuntap.sh "$USER"
ip addr show kanon          # expect: kanon, inet 10.0.1.1/24, MTU 1024
```

**Terminal 2 — server:**
```bash
./gradlew :server:run --args="8080"
# expect log: "Server listening on default port: 8080"
# verify in another shell:  ss -lun | grep 8080
```

**Terminal 3 — client:**
```bash
./gradlew :client:run --args="127.0.0.1 8080"
# expect logs: "Opened TUN/TAP device" and "Created TUN/TAP device"
```

**Terminal 4 — curl through the proxy:**
```bash
sudo curl -v --max-time 15 --interface kanon http://1.1.1.1/
```
Success looks like a real HTTP response from `1.1.1.1` (almost certainly a
`301 Moved Permanently` to HTTPS — that proves the round trip).

Tear-down:
```bash
# Ctrl-C terminal 3 (client), then terminal 2 (server)
bash client/scripts/cleanup.sh
ip link show kanon || echo "kanon gone"
```
If cleanup ever reports `kanon interface is still present`, run
`sudo lsof /dev/net/tun` to find what's still holding the fd.

### Watching packets while the demo runs

`kanon` is a regular kernel interface, so on Linux the easiest capture is
plain libpcap on the device itself. The in-process pcap-ng dumpers
([packetdumper](https://github.com/compscidr/packetdumper)) are also exposed
in case you want to see the proxy's egress side (and they're what the Android
app uses where you can't `tcpdump` the VPN interface from your laptop):

```bash
sudo wireshark -k -i kanon                  # client/TUN leg, native libpcap
wireshark -k -i TCP@127.0.0.1:19000         # client-side in-process dumper (same packets)
wireshark -k -i TCP@127.0.0.1:19001         # server-side dumper (proxy's outbound to public Internet)
```

See [Debugging with Wireshark](#debugging-with-wireshark) below for more on
the in-process dumpers.

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
