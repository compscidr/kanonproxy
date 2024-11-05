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
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import io.mockk.mockk
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.BeforeAll
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
        private val packetDumper = PcapNgTcpServerPacketDumper(isSimple = false)

        @JvmStatic
        @BeforeAll
        fun setup() {
            packetDumper.start()
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            packetDumper.stop()
        }
    }

    @BeforeEach
    fun setupEach(testInfo: TestInfo) {
        logger.debug("Starting test ${testInfo.displayName}")
        kAnonProxy.start()
        // Thread.sleep(5000) // uncomment for testing with wireshark to give time to connect
    }

    @AfterEach
    fun teardownEach(testInfo: TestInfo) {
        logger.debug("Ending test ${testInfo.displayName}")
        kAnonProxy.stop()
    }

    @Test fun udpDnsTest() {
        val dnsHeader =
            DnsHeader(
                id = 1u,
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
                listOf(DnsQName("mtalk"), DnsQName("google"), DnsQName("com")),
                DnsType.A,
                DnsQClass.IN,
            )
        val dnsMessage = DnsMessage(dnsHeader, listOf(question))
        val dnsMessageBuffer = dnsMessage.toByteArray()
        val stringPacketDumper = StringPacketDumper()
        logger.debug(
            "Sending DNS request with length {}: {}",
            dnsMessageBuffer.size,
            stringPacketDumper.dumpBufferToString(ByteBuffer.wrap(dnsMessageBuffer)),
        )
        val dnsServer = InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)

        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val sourcePort = Random.nextInt(1024, 65535)

        val udpHeader =
            UdpHeader(
                sourcePort.toUShort(),
                dnsServer.port.toUShort(),
                (dnsMessageBuffer.size.toUShort() + UdpHeader.UDP_HEADER_LENGTH).toUShort(),
                0u,
            )
        val ipHeader =
            Ipv4Header(
                sourceAddress = sourceAddress,
                destinationAddress = dnsServer.address as Inet4Address,
                protocol = IpType.UDP.value,
                totalLength =
                    (Ipv4Header.IP4_MIN_HEADER_LENGTH + udpHeader.totalLength).toUShort(),
            )
        val packet =
            Packet(
                ipHeader,
                udpHeader,
                dnsMessageBuffer,
            )
        packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = EtherType.DETECT)
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        packetDumper.dumpBuffer(ByteBuffer.wrap(response.toByteArray()), etherType = EtherType.DETECT)
        logger.debug("Got UDP response: {}", response.nextHeaders)

        val dnsResponse = DnsMessage.fromStream(ByteBuffer.wrap(response.payload))
        assertEquals(dnsHeader.id, dnsResponse.header.id)
        assertEquals(dnsHeader.qdCount, dnsResponse.header.qdCount)

        logger.debug("Got DNS response: {}", dnsResponse)
    }
}
