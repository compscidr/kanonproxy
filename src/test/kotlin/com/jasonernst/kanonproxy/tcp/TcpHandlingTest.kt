package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.testservers.server.TcpEchoServer
import io.mockk.mockk
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Disabled
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.nio.ByteBuffer

// this needs to be set to 250 if we want to test the TIME_WAIT state
@Timeout(20)
class TcpHandlingTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    companion object {
        val tcpEchoServer = TcpEchoServer()
        val kAnonProxy = KAnonProxy(ICMPLinux, mockk(relaxed = true))

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

    @BeforeEach fun setupEach(testInfo: TestInfo) {
        logger.debug("Starting test ${testInfo.displayName}")
        kAnonProxy.start()
    }

    @AfterEach fun teardownEach(testInfo: TestInfo) {
        logger.debug("Ending test ${testInfo.displayName}")
        kAnonProxy.stop()
    }

    @Test
    fun ipv4TcpHandshakeClose() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()
        tcpClient.closeClient()
    }

    /**
     * This takes takes a little bit more than 240s to run before the TIME_WAIT state is done. We might want to consider
     * reducing the MSL timer for this test to speed it up.
     */
    @Disabled("This test takes a long time to run")
    @Test
    fun ipv4TcpHandshakeCloseWaitForTimeWait() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()
        tcpClient.closeClient(true)
    }

    /**
     * Make sure we can handle a TCP session teardown, and then start back up with the same source and destination.
     * see: https://datatracker.ietf.org/doc/html/rfc9293#name-half-closed-connections
     */
    @Test
    fun ipv4TwoSubsequentTcpHandshakes() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()
        tcpClient.closeClient()
        logger.debug("First session closed")

        val tcpClient2 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient2.connect()
        tcpClient2.closeClient()
    }

    @Test fun ipv4TcpSendRecvEcho() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()

        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(payload.size)
        tcpClient.recv(recvBuffer)

        tcpClient.closeClient()

        assertArrayEquals(payload, recvBuffer.array())
    }

    /**
     * This test is for a second subsequent session after the first one has completed.
     */
    @Test fun ipv4TcpSendRecvEchoSecondSession() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient.connect()

        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(payload.size)
        tcpClient.recv(recvBuffer)

        tcpClient.closeClient()

        assertArrayEquals(payload, recvBuffer.array())

        val tcpClient2 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy)
        tcpClient2.connect()
        tcpClient2.closeClient()
    }

    // todo: ipv6 tests
}
