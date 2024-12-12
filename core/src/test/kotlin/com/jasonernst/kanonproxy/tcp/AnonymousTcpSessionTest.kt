package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.DummyProtector
import com.jasonernst.kanonproxy.SessionManager
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.transport.tcp.TcpHeader
import io.mockk.every
import io.mockk.mockk
import java.net.Inet4Address
import java.net.InetSocketAddress
import java.util.concurrent.LinkedBlockingDeque
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.slf4j.LoggerFactory

class AnonymousTcpSessionTest {
    private val logger = LoggerFactory.getLogger(javaClass)

    @Test fun twoSessions() {
        val clientAddress = InetSocketAddress("localhost", 8080)
        val ipHeader = Ipv4Header(sourceAddress = Inet4Address.getByName("127.0.0.1") as Inet4Address, destinationAddress = Inet4Address.getByName("xkcd.com") as Inet4Address, protocol = IpType.TCP.value)
        val tcpHeader = TcpHeader(syn = true, destinationPort = 80u)
        val returnQueue = LinkedBlockingDeque<Packet>()

        val sessionManager = mockk<SessionManager>()
        every { sessionManager.isRunning() } returns true

        val session = AnonymousTcpSession(ipHeader, tcpHeader, ByteArray(0), returnQueue, DummyProtector, sessionManager, clientAddress)

        // wait until its connecting
        while (session.isConnecting.get().not()) {
            Thread.sleep(100)
        }

        // wait until its no longer connecting
        while (session.isConnecting.get()) {
            Thread.sleep(100)
        }
        assertTrue(session.channel.isConnected)


        val ipHeader2 = Ipv4Header(sourceAddress = Inet4Address.getByName("127.0.0.1") as Inet4Address, destinationAddress = Inet4Address.getByName("xkcd.com") as Inet4Address, protocol = IpType.TCP.value)
        val tcpHeader2 = TcpHeader(syn = true, destinationPort = 80u)
        val returnQueue2 = LinkedBlockingDeque<Packet>()
        val session2 = AnonymousTcpSession(ipHeader2, tcpHeader2, ByteArray(0), returnQueue2, DummyProtector, sessionManager, clientAddress)

        // wait until its connecting
        while (session2.isConnecting.get().not()) {
            Thread.sleep(100)
        }

        // wait until its no longer connecting
        while (session2.isConnecting.get()) {
            Thread.sleep(100)
        }
        assertTrue(session2.channel.isConnected)
    }
}