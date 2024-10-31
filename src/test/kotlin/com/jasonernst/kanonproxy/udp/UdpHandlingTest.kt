package com.jasonernst.kanonproxy.udp

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.testservers.server.UdpEchoServer
import io.mockk.mockk
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

@Timeout(20)
class UdpHandlingTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val kAnonProxy = KAnonProxy(IcmpLinux, mockk(relaxed = true))

    companion object {
        val udpEchoServer: UdpEchoServer = UdpEchoServer()

        @JvmStatic
        @BeforeAll
        fun setup() {
            udpEchoServer.start()
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            udpEchoServer.stop()
        }
    }

    @BeforeEach
    fun setupEach(testInfo: TestInfo) {
        logger.debug("Starting test ${testInfo.displayName}")
        kAnonProxy.start()
    }

    @AfterEach
    fun teardownEach(testInfo: TestInfo) {
        logger.debug("Ending test ${testInfo.displayName}")
        kAnonProxy.stop()
    }

    @Test fun testIpv4UdpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
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
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        logger.debug("Got response: {}", response.nextHeaders)
        val parsedPayload = response.payload
        Assertions.assertArrayEquals(payload, parsedPayload)
    }

    @Test fun testIpv6UdpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("::1") as Inet6Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("::1") as Inet6Address
        val destinationPort: UShort = UdpEchoServer.UDP_DEFAULT_PORT.toUShort()
        val udpHeader = UdpHeader(sourcePort, destinationPort, payload.size.toUShort(), 0u)
        val packet =
            Packet(
                Ipv6Header(
                    sourceAddress = sourceAddress,
                    destinationAddress = destinationAddress,
                    protocol = IpType.UDP.value,
                    payloadLength = (udpHeader.totalLength + payload.size.toUShort()).toUShort(),
                ),
                udpHeader,
                payload,
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        logger.debug("Got response: {}", response.nextHeaders)
        val parsedPayload = response.payload
        Assertions.assertArrayEquals(payload, parsedPayload)
    }
}
