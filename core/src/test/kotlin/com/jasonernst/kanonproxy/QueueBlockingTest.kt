package com.jasonernst.kanonproxy

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.icmp.IcmpHandlingTest.Companion.UNREACHABLE_IPV4
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v4.Ipv4Header.Companion.IP4_MIN_HEADER_LENGTH
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import com.jasonernst.testservers.server.UdpEchoServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress

@Timeout(6)
class QueueBlockingTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val kAnonProxy = KAnonProxy(IcmpLinux)
    private val clientAddress = InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234)

    companion object {
        private val udpEchoServer: UdpEchoServer = UdpEchoServer()

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

    @Test @BeforeEach
    fun beforeEach() {
        kAnonProxy.start()
    }

    @Test @AfterEach
    fun afterEach() {
        kAnonProxy.stop()
    }

    // if this test fails, the TCP connection handling is blocking the queue and the UDP packet can't get through
    // if it succeeds, the TCP connection handling happens simultaneously with the UDP packet handling
    @Test
    fun slowConnectionDoesntBlockQueue() {
        val tcpSyn = TcpHeader(syn = true)
        val tcpIpHeader =
            Ipv4Header(
                destinationAddress = InetAddress.getByName(UNREACHABLE_IPV4) as Inet4Address,
                protocol = IpType.TCP.value,
                totalLength =
                    (
                        IP4_MIN_HEADER_LENGTH +
                            tcpSyn.getHeaderLength()
                    ).toUShort(),
            )
        val tcpPacket = Packet(tcpIpHeader, tcpSyn, ByteArray(0))

        val udpPayload = "Test Data".toByteArray()
        val udpHeader = UdpHeader(12345u, UdpEchoServer.UDP_DEFAULT_PORT.toUShort(), udpPayload.size.toUShort(), 0u)
        val udpIpHeader =
            Ipv4Header(
                destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address,
                protocol = IpType.UDP.value,
                totalLength =
                    (
                        IP4_MIN_HEADER_LENGTH +
                            udpHeader.totalLength +
                            udpPayload.size.toUShort()
                    ).toUShort(),
            )
        val udpPacket = Packet(udpIpHeader, udpHeader, udpPayload)

        kAnonProxy.handlePackets(listOf(tcpPacket, udpPacket), clientAddress)

        // we expect the UDP echo server to return the echo before we get the destination unreachable message about the
        // TCP syn
        val recvPacket = kAnonProxy.takeResponse(clientAddress)
        logger.info("Received packet: $recvPacket")
        assertTrue(recvPacket.ipHeader != null)

        assertTrue(recvPacket.ipHeader!!.protocol == IpType.UDP.value)
        val recvPacket2 = kAnonProxy.takeResponse(clientAddress)
        logger.info("Received packet: $recvPacket2")
        assertTrue(recvPacket2.ipHeader != null)
        // should be a destination unreachable message
        assertTrue(recvPacket2.ipHeader!!.protocol == IpType.ICMP.value)
    }
}
