package com.jasonernst.kanonproxy

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.KAnonProxy.Companion.STALE_SESSION_MS
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.testservers.server.UdpEchoServer
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress

@Timeout(10)
class KAnonProxyTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val clientAddress = InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234)

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

    @Test fun startStop() {
        val kAnonProxy = KAnonProxy(IcmpLinux)
        kAnonProxy.start()
        kAnonProxy.stop()
    }

    @Test fun udpSessionTimeout() {
        val kAnonProxy = KAnonProxy(IcmpLinux)
        kAnonProxy.start()

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
        kAnonProxy.handlePackets(listOf(packet), clientAddress)
        val response = kAnonProxy.takeResponse(clientAddress)
        logger.debug("Got response: {}", response.nextHeaders)
        val parsedPayload = response.payload
        Assertions.assertArrayEquals(payload, parsedPayload)
        assertTrue(
            kAnonProxy.haveSessionForClient(
                clientAddress,
                Session.getKey(sourceAddress, sourcePort, destinationAddress, destinationPort, IpType.UDP.value),
            ),
        )

        runBlocking {
            delay(STALE_SESSION_MS + 1000)
        }
        assertFalse(
            kAnonProxy.haveSessionForClient(
                clientAddress,
                Session.getKey(sourceAddress, sourcePort, destinationAddress, destinationPort, IpType.UDP.value),
            ),
        )

        kAnonProxy.stop()
    }

    @Test fun stopWithActiveSessions() {
        val kAnonProxy = KAnonProxy(IcmpLinux)
        kAnonProxy.start()

        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("0.0.0.0") as Inet4Address
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
        kAnonProxy.handlePackets(listOf(packet), clientAddress)
        kAnonProxy.stop()
    }
}
