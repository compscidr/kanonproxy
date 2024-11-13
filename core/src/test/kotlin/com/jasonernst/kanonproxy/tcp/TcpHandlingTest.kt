package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.kanonproxy.icmp.IcmpHandlingTest
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
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
import org.junit.jupiter.api.assertThrows
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.SocketException
import java.nio.ByteBuffer

// this needs to be set to 250 if we want to test the TIME_WAIT state
@Timeout(20)
class TcpHandlingTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val kAnonProxy = KAnonProxy(IcmpLinux, mockk(relaxed = true))

    companion object {
        private val tcpEchoServer = TcpEchoServer()
        private val packetDumper = PcapNgTcpServerPacketDumper(isSimple = false)
        private val staticLogger = LoggerFactory.getLogger(TcpHandlingTest::class.java)

        @JvmStatic
        @BeforeAll
        fun setup() {
            tcpEchoServer.start()
            packetDumper.start()
            staticLogger.debug("Delaying to connect to wireshark")
            Thread.sleep(5000)
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            tcpEchoServer.stop()
            packetDumper.stop()
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
        val destinationAddress = InetAddress.getByName("0.0.0.0") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()
        logger.debug("Connect finished, closing client")
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

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
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

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()
        tcpClient.closeClient()
        logger.debug("First session closed")
        kAnonProxy.flushQueue(tcpClient.clientAddress)

        val tcpClient2 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient2.connect()
        tcpClient2.closeClient()
    }

    @Test fun ipv4TcpSendRecvEcho() {
        val payload = "Test Data".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
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
        val destinationAddress = InetAddress.getByName("0.0.0.0") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()

        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(payload.size)
        tcpClient.recv(recvBuffer)

        tcpClient.closeClient()
        kAnonProxy.flushQueue(tcpClient.clientAddress)

        assertArrayEquals(payload, recvBuffer.array())

        val tcpClient2 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient2.connect()
        tcpClient2.closeClient()
    }

    @Test fun ipv4TcpSendRecvMultipleEcho() {
        val payload = "Payload1".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("0.0.0.0") as Inet4Address
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()

        // send, recv
        tcpClient.send(ByteBuffer.wrap(payload))
        val recvBuffer = ByteBuffer.allocate(payload.size)
        tcpClient.recv(recvBuffer)

        // send, recv
        val payload2 = "Payload2".toByteArray()
        tcpClient.send(ByteBuffer.wrap(payload2))
        val recvBuffer2 = ByteBuffer.allocate(payload2.size)
        tcpClient.recv(recvBuffer2)

        // send, send, rcv
        tcpClient.send(ByteBuffer.wrap(payload))
        tcpClient.send(ByteBuffer.wrap(payload2))
        val recvBuffer3 = ByteBuffer.allocate(payload.size + payload2.size)

        // may take multiple recvs because the server may send the data in multiple packets
        while (recvBuffer3.position() < payload.size + payload2.size) {
            tcpClient.recv(recvBuffer3)
        }

        tcpClient.closeClient()

        assertArrayEquals(payload, recvBuffer.array())
        assertArrayEquals(payload2, recvBuffer2.array())
        assertArrayEquals(payload + payload2, recvBuffer3.array())
    }

    @Test
    fun ipv4TcpUnreachable() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName(IcmpHandlingTest.UNREACHABLE_IPV4)
        val destinationPort: UShort = TcpEchoServer.TCP_DEFAULT_PORT.toUShort()

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        assertThrows<SocketException> { tcpClient.connect(2000) }
    }

    @Test
    fun ipv4TcpHttp() {
        val payload = "GET / HTTP/1.1\r\nHost: xkcd.com\r\n\r\n".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("xkcd.com") as Inet4Address
        logger.debug("Destination address: ${destinationAddress.hostAddress}")
        val destinationPort: UShort = 80u

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()
        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
        tcpClient.recv(recvBuffer)

        tcpClient.closeClient()
        logger.debug("Starting session 2")
        kAnonProxy.flushQueue(tcpClient.clientAddress)

        val tcpClient2 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient2.connect()
        tcpClient2.send(ByteBuffer.wrap(payload))

        tcpClient2.recv(recvBuffer)
        tcpClient2.closeClient()

        kAnonProxy.flushQueue(tcpClient.clientAddress)
        logger.debug("Starting session 3")

        val tcpClient3 = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient3.connect()
        tcpClient3.send(ByteBuffer.wrap(payload))
        tcpClient3.recv(recvBuffer)
        tcpClient3.closeClient()
    }

    @Disabled("WiP")
    @Test
    fun ipv4TcpHttp1Mb() {
        val payload = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".toByteArray()
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort: UShort = 12345u
        val destinationAddress = InetAddress.getByName("0.0.0.0") as Inet4Address
        val destinationPort: UShort = 80u

        val tcpClient = TcpClient(sourceAddress, destinationAddress, sourcePort, destinationPort, kAnonProxy, packetDumper)
        tcpClient.connect()
        tcpClient.send(ByteBuffer.wrap(payload))

        val recvBuffer = ByteBuffer.allocate(1024 * 1024)
        var totalReceived = 0
        do {
            tcpClient.recv(recvBuffer)

            // if we have a response, print it out
            var gotResponse = false
            if (recvBuffer.position() > 0) {
                gotResponse = true
                val response = ByteArray(recvBuffer.position())
                recvBuffer.flip()
                recvBuffer.get(response)
                totalReceived += response.size
                logger.debug("Received ${response.size} bytes, for a total of $totalReceived")
            }
            recvBuffer.clear()
        } while (gotResponse)
        tcpClient.closeClient()

        tcpClient.closeClient()
    }

    // todo: ipv6 tests
}