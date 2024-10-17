package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.kanonproxy.Session
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.TcpHeaderFactory
import com.jasonernst.testservers.server.TcpEchoServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.Inet4Address
import java.net.InetAddress
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.slf4j.LoggerFactory

@Timeout(20)
class TcpHandlingTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    companion object {
        val tcpEchoServer = TcpEchoServer()

        @JvmStatic
        @BeforeAll
        fun setup() {
            tcpEchoServer.start()
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            tcpEchoServer.stop()
        }
    }

    fun handshake(sourceAddress: InetAddress, destinationAddress: InetAddress, sourcePort: UShort, destinationPort: UShort, startingSequence: UInt, mss: UShort, kAnonProxy: KAnonProxy) {
        val sessionKey =
            Session.getKey(sourceAddress, sourcePort, destinationAddress, destinationPort, IpType.TCP.value)
        logger.debug("Handshake for session: $sessionKey")
        assertFalse(kAnonProxy.sessionTableBySessionKey.contains(sessionKey))
        val synPacket =
            TcpHeaderFactory.createSynPacket(
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                startingSequence,
                mss,
            )
        kAnonProxy.handlePackets(listOf(synPacket))
        val expectedSynAck = kAnonProxy.takeResponse()
        val session = kAnonProxy.sessionTableBySessionKey.get(sessionKey) as TcpSession
        assertEquals(TcpState.SYN_RECEIVED, session.tcpStateMachine.tcpState)
        assertTrue(expectedSynAck.nextHeaders is TcpHeader)
        val expectedSynAckTcpHeader = expectedSynAck.nextHeaders as TcpHeader
        assertTrue(expectedSynAckTcpHeader.isSyn())
        assertTrue(expectedSynAckTcpHeader.isAck())
        assertEquals(startingSequence + 1u, expectedSynAckTcpHeader.acknowledgementNumber)
        logger.debug("Got SYN-ACK: {}", expectedSynAckTcpHeader)

        val ack = TcpHeaderFactory.createAckPacket(expectedSynAck.ipHeader, expectedSynAckTcpHeader, expectedSynAckTcpHeader.acknowledgementNumber + 1u, expectedSynAckTcpHeader.sequenceNumber)
        kAnonProxy.handlePackets(listOf(ack))
        assertEquals(TcpState.ESTABLISHED, session.tcpStateMachine.tcpState)
    }

    @Test fun testIpv4TcpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()
        val startingSequence = 0u
        val mss: UShort = 1500u

        val kAnonProxy = KAnonProxy(ICMPLinux)
        handshake(sourceAddress, destinationAddress, sourcePort, destinationPort, startingSequence, mss, kAnonProxy)
    }

    @Test fun testIpv6TcpPacketHandling() {
    }
}
