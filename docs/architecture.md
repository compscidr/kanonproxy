# Architecture: how knet, icmp, and packetdumper fit into kanonproxy

This is an onboarding-oriented map of how the three external libraries
[knet](https://github.com/compscidr/knet),
[icmp](https://github.com/compscidr/icmp), and
[packetdumper](https://github.com/compscidr/packetdumper) interact with the
four kanonproxy modules (`core`, `client`, `server`, `android`).

## 1. Repo relationships at a glance

```mermaid
flowchart TD
    knet["<b>knet</b><br/>parses raw IP bytes<br/>into Packet objects;<br/>serializes them back"]
    icmp["<b>icmp</b><br/>sends real ICMP echoes;<br/>platform-specific:<br/>IcmpLinux / IcmpAndroid"]
    pd["<b>packetdumper</b><br/>writes pcap-ng / hex-dump<br/>captures to a file or<br/>live TCP server"]

    subgraph kanon["<b>kanonproxy</b>"]
        direction LR
        core["<b>core</b><br/>proxy logic &amp; sessions"]
        client["<b>client</b><br/>TUN/VPN ↔ proxy server"]
        server["<b>server</b><br/>UDP listener for clients"]
        android["<b>android</b><br/>sample VPN app"]
    end

    knet -- "Packet, IpHeader, TcpHeader,<br/>UdpHeader, IcmpFactory, …" --> kanon
    icmp -- "Icmp.ping(),<br/>IcmpV4/V6EchoPacket,<br/>DestinationUnreachable…" --> kanon
    pd -- "AbstractPacketDumper,<br/>PcapNgTcpServerPacketDumper,<br/>DummyPacketDumper, EtherType" --> kanon

    classDef lib fill:#4f6df0,stroke:#1a2a8c,stroke-width:2px,color:#ffffff;
    classDef mod fill:#2da44e,stroke:#1a6b34,stroke-width:2px,color:#ffffff;
    classDef group fill:#1f6feb22,stroke:#58a6ff,stroke-width:2px,color:#c9d1d9;
    class knet,icmp,pd lib;
    class core,client,server,android mod;
    class kanon group;
```

knet, icmp, and packetdumper are independent libraries (separate repos,
separate Maven Central artifacts) that kanonproxy depends on:

- **knet** — "what is this packet?" Parses raw IP bytes into typed `Packet`
  objects and serializes them back.
- **icmp** — "actually emit a real ping." Provides the platform-specific raw-
  socket implementations (`IcmpLinux`, `IcmpAndroid`).
- **packetdumper** — "see what's flowing through." An optional observability
  hook injected into `ProxyServer` / `ProxyClient` / `KAnonVpnService` that
  dumps every packet to a pcap-ng stream (live-tailable from Wireshark via
  `wireshark -k -i TCP@127.0.0.1:19000`) or to a file. `DummyPacketDumper`
  is the no-op default so it costs nothing in production.

kanonproxy stitches these together with its own session management, TCP
state machine, and platform glue.

## 2. Data flow — one packet round-trip

```mermaid
flowchart TD
    os[("OS / TUN-TAP / Android VPN<br/>raw IP byte stream")]

    subgraph clientMod["<b>client/</b> — LinuxProxyClient · AndroidClient extend ProxyClient"]
        cParse["knet: Packet.parseStream"]
        cChan["DatagramChannel<br/>(UDP to server)"]
        cWrite["tunWrite ← packet.toByteArray()"]
        cParse -- "parsed Packets" --> cChan
        cChan -- "from server" --> cWrite
    end

    subgraph serverMod["<b>server/</b> — ProxyServer"]
        sRead["readFromClient()<br/>knet: Packet.parseStream"]
        sHandle["kAnonProxy.handlePackets()"]
        sTake["kAnonProxy.takeResponse()<br/>via ProxySession"]
        sOut["enqueueOutgoing(buffer)"]
        sRead --> sHandle
        sTake --> sOut
    end

    subgraph coreMod["<b>core/</b> — KAnonProxy (pure logic, no I/O of its own)"]
        kHandle["handlePacket(packet)"]
        kSess["Session table<br/>(per clientAddress, per 5-tuple)"]
        kTcpUdp["AnonymousTcpSession / UdpSession<br/>real SocketChannel / DatagramChannel"]
        kIcmp["icmp.ping(destination)<br/>→ Success: IcmpV4/V6EchoPacket reply<br/>→ Failure: DestinationUnreachable"]
        kErr["Session.handleExceptionOnRemoteChannel<br/>→ knet:IcmpFactory.createDestinationUnreachable"]
        kHandle -- "TransportHeader (knet)" --> kSess --> kTcpUdp
        kHandle -- "IcmpNextHeaderWrapper (knet)" --> kIcmp
        kTcpUdp -.->|on connect failure| kErr
    end

    pdLib(["<b>packetdumper</b><br/>dumpBuffer(...)"])
    icmpLib(["<b>icmp</b> lib<br/>IcmpLinux / IcmpAndroid"])
    inet[("public Internet")]

    os -- "bytes in" --> cParse
    cWrite -- "bytes out" --> os
    cChan == "UDP" ==> sRead
    sOut == "UDP" ==> cChan
    sHandle == "Packet (knet)" ==> kHandle
    kTcpUdp -- "responses" --> sTake
    kIcmp -- "responses" --> sTake

    kTcpUdp <--> inet
    kIcmp <-.-> icmpLib

    cParse -.->|each packet| pdLib
    cWrite -.->|each packet| pdLib
    sRead -.->|each packet| pdLib
    sOut -.->|each packet| pdLib

    classDef ext fill:#d97706,stroke:#7c4a06,stroke-width:2px,color:#ffffff;
    classDef io fill:#6b7280,stroke:#1f2937,stroke-width:2px,color:#ffffff;
    classDef node fill:#1f6feb,stroke:#0d419d,stroke-width:2px,color:#ffffff;
    classDef group fill:#1f6feb22,stroke:#58a6ff,stroke-width:2px,color:#c9d1d9;
    class pdLib,icmpLib ext;
    class os,inet io;
    class cParse,cChan,cWrite,sRead,sHandle,sTake,sOut,kHandle,kSess,kTcpUdp,kIcmp,kErr node;
    class clientMod,serverMod,coreMod group;
```

## 3. Library responsibilities — who owns what

| Concern | Library | What it gives kanonproxy |
|---|---|---|
| Parse a raw IP byte stream into objects | **knet** | `Packet.parseStream(ByteBuffer)` |
| IP / TCP / UDP / ICMP header data classes (read + serialize) | **knet** | `Ipv4Header`, `Ipv6Header`, `TcpHeader`, `UdpHeader`, `IcmpNextHeaderWrapper`, `IcmpFactory` |
| Serialize a `Packet` back to bytes | **knet** | `packet.toByteArray()` |
| Actually emit ICMP echo to the real network | **icmp** | `Icmp.ping(InetAddress)` — `IcmpLinux` (raw socket) on JVM, `IcmpAndroid` on Android |
| ICMP echo / destination-unreachable packet types and codes | **icmp** | `IcmpV4EchoPacket`, `IcmpV6EchoPacket`, `IcmpV4/V6DestinationUnreachablePacket`, `IcmpV4/V6DestinationUnreachableCodes` |
| Capture a copy of every packet for debugging | **packetdumper** | `AbstractPacketDumper.dumpBuffer(ByteBuffer, EtherType)` |
| Live pcap-ng stream consumable by Wireshark | **packetdumper** | `PcapNgTcpServerPacketDumper` (default port 19000) |
| No-op dumper for production / tests | **packetdumper** | `DummyPacketDumper` |

Key point: **knet handles every other protocol end-to-end** (parse + build + serialize).
For TCP and UDP, kanonproxy itself opens the outbound connections using ordinary
`SocketChannel` / `DatagramChannel` instances inside `AnonymousTcpSession` / `UdpSession`.
**ICMP is the exception**: because emitting a real ICMP echo requires privileged raw-socket
access (and differs between Linux and Android), that emission is delegated to the icmp
library via `Icmp.ping(...)`, with `IcmpLinux` / `IcmpAndroid` providing the platform
implementation.

## 4. Where each library is wired in

- **`KAnonProxy(icmp: Icmp, ...)`** — single constructor injection point. Caller passes
  `IcmpLinux` (server `main`) or `IcmpAndroid` (`KAnonVpnService` on Android).
- **`ProxyServer`** parses inbound UDP from clients with `Packet.parseStream` (knet) and
  forwards into `KAnonProxy`. Also accepts an `AbstractPacketDumper` (packetdumper) and
  calls `dumpBuffer(...)` on every packet in both directions; `ProxyServer.main` boots a
  `PcapNgTcpServerPacketDumper` on port `DEFAULT_PORT + 1`.
- **`ProxyClient`** parses both directions with knet — TUN→proxy and proxy→TUN — and
  dumps each packet through its injected `AbstractPacketDumper`.
- **`KAnonVpnService`** (android) wires a `PcapNgTcpServerPacketDumper` into the
  in-process `ProxyServer` / `AndroidClient` so on-device captures can be tailed live
  from Wireshark.
- **`Session.handleExceptionOnRemoteChannel`** uses knet's `IcmpFactory` to fabricate a
  "host unreachable" reply when a TCP/UDP outbound connect fails — so even non-ICMP
  failures synthesize ICMP responses, and that synthesis lives in knet.
