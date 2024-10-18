package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.testservers.server.TcpEchoServer
import io.mockk.mockk
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer

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

    @Test fun testIpv4TcpHandshakeClose() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val kAnonProxy = KAnonProxy(ICMPLinux, mockk())
        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()
        tcpClient.close()
    }

    @Test fun testIpv4TcpPacketHandling() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val kAnonProxy = KAnonProxy(ICMPLinux, mockk())
        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()

        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(payload.size)
        tcpClient.recv(recvBuffer)

        tcpClient.close()

        assertArrayEquals(payload, recvBuffer.array())
    }

    @Test fun testIpv6TcpPacketHandling() {
    }
}
