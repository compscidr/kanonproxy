package com.jasonernst.kanonproxy

import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.testservers.server.UdpEchoServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.InetAddress

@Timeout(20)
class UdpHandlingTest {
    companion object {
        val udpEchoServer: UdpEchoServer = UdpEchoServer()

        @JvmStatic
        @BeforeAll fun setup() {
            udpEchoServer.start()
        }

        @JvmStatic
        @AfterAll fun teardown() {
            udpEchoServer.stop()
        }
    }

    @Test fun testIpv4UdpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1")
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1")
        val destinationPort: UShort = UdpEchoServer.UDP_DEFAULT_PORT.toUShort()
        val udpHeader = UdpHeader(sourcePort, destinationPort, payload.size.toUShort(), 0u)
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
        val kAnonProxy = KAnonProxy(ICMPLinux)
        kAnonProxy.handlePackets(listOf(packet))

        val response = kAnonProxy.takeResponse()
        println("Got response: ${response.nextHeaders}")
    }

    @Test fun testIpv6UdpPacketHandling() {
    }
}
