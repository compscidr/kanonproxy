# kanonproxy
[![JVM Tests](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml/badge.svg)](https://github.com/compscidr/kanonproxy/actions/workflows/test.yml)&nbsp;
[![codecov](https://codecov.io/gh/compscidr/kanonproxy/graph/badge.svg?token=yBstrWw9Mm)](https://codecov.io/gh/compscidr/kanonproxy)&nbsp;

An anonymous proxy written in kotlin. 

This project is meant to be a library that can run on android or linux. It does not provide
the client / server functionality. It is able to process packets which have been parsed
by https://github.com/compscidr/knet, manage sessions and make outgoing anonymous requests
based on the incoming traffic. It also receives the return traffic, and puts them into a
queue. 

It is up to consumers of the this library to implement a server or a tun/tap adapter, or a
VPN service on Android to make use of this library.

## Usage
The examples below show a contrived example where the packets are manually constructed. This
is a valid usecase, however, you probably want instead to parse a stream from an OS via a
TUN/TAP driver, or an Android VPN iostream or something. This library takes a list of 
the `Packet` type from the knet library https://github.com/compscidr/knet, so if you have a
stream, you can convert that stream into a list of packets by parsing it with that lib.

The other thing to note is that in order to handle ICMP traffic, we use the icmp library:
https://github.com/compscidr/icmp. Depending on whether you are on linux or android, you
should pass the appropriate `ICMP` object to the proxy. On linux its `ICMPLinux` on android
its `ICMPAndroid`. You also need to use different dependencies for each. For linux
`implementation("com.jasonernst.icmp:icmp-linux")` and for android 
`implementation("com.jasonernst.icmp:icmp-android")`

Linux:
```kotlin
val kanonProxy = KAnonProxy(ICMPLinux)

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

There are more examples of usage in the [tests](src/test/kotlin/com/jasonernst/kanonproxy)