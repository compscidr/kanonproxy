package com.jasonernst.kanonproxy.dns

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.Packet
import com.jasonernst.knet.application.dns.DnsHeader
import com.jasonernst.knet.application.dns.DnsMessage
import com.jasonernst.knet.application.dns.DnsQClass
import com.jasonernst.knet.application.dns.DnsQName
import com.jasonernst.knet.application.dns.DnsQuestion
import com.jasonernst.knet.application.dns.DnsType
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.transport.udp.UdpHeader
import io.mockk.mockk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import kotlin.random.Random

class DnsTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val kAnonProxy = KAnonProxy(IcmpLinux, mockk(relaxed = true))

    companion object {
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

    @Test fun udpDnsTest() {
        val dnsHeader =
            DnsHeader(
                id = 0u,
                response = false,
                opcode = 0u,
                aa = false,
                tc = false,
                rd = true,
                ra = false,
                rcode = 0u,
                qdCount = 1u,
                anCount = 0u,
                nsCount = 0u,
                arCount = 0u,
            )
        val question =
            DnsQuestion(
                listOf(DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = dnsMessage.toByteArray()
        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)

        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort = Random.nextInt(1024, 65535)

        val udpHeader =
            UdpHeader(
                sourcePort.toUShort(),
                dnsServer.port.toUShort(),
                dnsMessageBuffer.size.toUShort(),
                0u,
            )
        val packet =
            Packet(
                Ipv4Header(
                    sourceAddress = sourceAddress,
                    destinationAddress = dnsServer.address as Inet4Address,
                    protocol = IpType.UDP.value,
                    totalLength =
                        (
                            Ipv4Header.IP4_MIN_HEADER_LENGTH +
                                udpHeader.totalLength +
                                dnsMessageBuffer.size.toUShort()
                        ).toUShort(),
                ),
                udpHeader,
                dnsMessageBuffer,
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        logger.debug("Got UDP response: {}", response.nextHeaders)

        val dnsResponse = DnsMessage.fromStream(ByteBuffer.wrap(response.payload))
        assertEquals(dnsHeader.id, dnsResponse.header.id)
        assertEquals(dnsHeader.qdCount, dnsResponse.header.qdCount)

        logger.debug("Got DNS response: {}", dnsResponse)
    }
}
