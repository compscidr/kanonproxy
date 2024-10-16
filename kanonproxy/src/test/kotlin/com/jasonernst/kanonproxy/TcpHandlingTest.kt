package com.jasonernst.kanonproxy

import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.knet.transport.tcp.TcpHeaderFactory
import com.jasonernst.testservers.server.TcpEchoServer
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.net.Inet4Address
import java.net.InetAddress

@Timeout(20)
class TcpHandlingTest {
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

    @Test fun testIpv4TcpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()
        val startingSequence = 0u
        val mss: UShort = 1500u

        val synPacket =
            TcpHeaderFactory.createSynPacket(
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                startingSequence,
                mss,
            )
        val kAnonProxy = KAnonProxy(ICMPLinux)
        kAnonProxy.handlePackets(listOf(synPacket))

        val expectedSynAck = kAnonProxy.takeResponse()
    }

    @Test fun testIpv6TcpPacketHandling() {
    }
}
