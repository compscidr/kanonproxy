# Architecture: how knet and icmp fit into kanonproxy

This is an onboarding-oriented map of how the two external libraries
[knet](https://github.com/compscidr/knet) and [icmp](https://github.com/compscidr/icmp)
interact with the four kanonproxy modules (`core`, `client`, `server`, `android`).

## 1. Data flow — one packet round-trip

```
┌─────────────────────────────────────────────────────────────────────────┐
│  OS / TUN-TAP / Android VPN  (raw IP byte stream)                       │
└─────────────────────┬───────────────────────────────────▲───────────────┘
                      │ bytes in                          │ bytes out
                      ▼                                   │
┌─────────────────────────────────────────────────────────────────────────┐
│  client/  (LinuxProxyClient · AndroidClient extend ProxyClient)         │
│                                                                         │
│   tunRead() ──▶ ┌──────────────┐    parsed Packets    ┌──────────────┐  │
│                 │ knet:        │  ───────────────▶    │ DatagramChan │  │
│                 │ Packet       │                      │ (UDP to      │  │
│                 │ .parseStream │                      │  server)     │  │
│                 └──────────────┘                      └──────┬───────┘  │
│                                                              │          │
│   tunWrite() ◀──── packet.toByteArray() ◀── parseStream ◀────┘          │
└─────────────────────────────────────────────────────────────────────────┘
                      │ UDP                              ▲ UDP
                      ▼                                  │
┌─────────────────────────────────────────────────────────────────────────┐
│  server/ ProxyServer                                                    │
│                                                                         │
│   readFromClient() ─▶ knet:Packet.parseStream(buffer) ──┐               │
│                                                         ▼               │
│                                              kAnonProxy.handlePackets() │
│                                                                         │
│   enqueueOutgoing(buffer) ◀── ProxySession ◀── kAnonProxy.takeResponse()│
└─────────────────────────────────────────────────────────────────────────┘
                      │                                  ▲
                      ▼ Packet (knet types)              │ Packet (knet types)
┌─────────────────────────────────────────────────────────────────────────┐
│  core/ KAnonProxy   (the brain — pure logic, no I/O of its own)         │
│                                                                         │
│   handlePacket(packet)                                                  │
│     ├─ packet.nextHeaders is TransportHeader (knet)                     │
│     │     └─▶ Session table (per clientAddress, per 5-tuple)            │
│     │           ├─ UdpSession  ──┐                                      │
│     │           └─ AnonymousTcp ─┤  real OS Socket/DatagramChannel      │
│     │              Session       │  ──▶ public Internet                 │
│     │                            ▼                                      │
│     │                     trafficAccounting + VpnProtector              │
│     │                                                                   │
│     └─ packet.nextHeaders is IcmpNextHeaderWrapper (knet)               │
│           └─▶ icmp.ping(destination)   ◀── icmp lib (IcmpLinux/Android) │
│                 ├─ Success ─▶ build IcmpV4/V6EchoPacket reply           │
│                 └─ Failure ─▶ IcmpV4/V6DestinationUnreachablePacket     │
│                       (wrap in knet Ipv4Header/Ipv6Header → outQueue)   │
│                                                                         │
│   Session error path: Session.handleExceptionOnRemoteChannel()          │
│     └─▶ knet:IcmpFactory.createDestinationUnreachable(...)              │
│         (uses icmp lib's V4/V6 unreachable codes as enum values)        │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Library responsibilities — who owns what

| Concern | Library | What it gives kanonproxy |
|---|---|---|
| Parse a raw IP byte stream into objects | **knet** | `Packet.parseStream(ByteBuffer)` |
| IP / TCP / UDP / ICMP header data classes (read + serialize) | **knet** | `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpNextHeaderWrapper`, `IcmpFactory` |
| Serialize a `Packet` back to bytes | **knet** | `packet.toByteArray()` |
| Actually emit ICMP echo to the real network | **icmp** | `Icmp.ping(InetAddress)` — `IcmpLinux` (raw socket) on JVM, `IcmpAndroid` on Android |
| ICMP echo / destination-unreachable packet types and codes | **icmp** | `IcmpV4EchoPacket`, `IcmpV6EchoPacket`, `IcmpV4/V6DestinationUnreachablePacket`, `IcmpV4/V6DestinationUnreachableCodes` |

Key point: **knet handles every other protocol end-to-end** (parse + build + serialize).
**icmp is the only protocol where kanonproxy actually opens an outbound socket of its own** —
TCP/UDP get a normal `SocketChannel`/`DatagramChannel`, but ICMP needs raw-socket privileges,
so it's delegated to the icmp lib (which has platform-specific implementations).

## 3. Where each library is wired in

- **`KAnonProxy(icmp: Icmp, ...)`** — single constructor injection point. Caller passes
  `IcmpLinux` (server `main`) or `IcmpAndroid` (`KAnonVpnService` on Android).
- **`ProxyServer`** parses inbound UDP from clients with `Packet.parseStream` (knet) and
  forwards into `KAnonProxy`.
- **`ProxyClient`** parses both directions with knet — TUN→proxy and proxy→TUN.
- **`Session.handleExceptionOnRemoteChannel`** uses knet's `IcmpFactory` to fabricate a
  "host unreachable" reply when a TCP/UDP outbound connect fails — so even non-ICMP
  failures synthesize ICMP responses, and that synthesis lives in knet.
