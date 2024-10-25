package com.jasonernst.kanonproxy.icmp

import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachablePacket
import com.jasonernst.icmp_common.v4.ICMPv4EchoPacket
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachablePacket
import com.jasonernst.icmp_common.v6.ICMPv6EchoPacket
import com.jasonernst.icmp_linux.ICMPLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.ICMPNextHeaderWrapper
import io.mockk.mockk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInfo
import org.junit.jupiter.api.Timeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

@Timeout(20)
class IcmpHandlingTest {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val kAnonProxy = KAnonProxy(ICMPLinux, mockk(relaxed = true))

    companion object {
        // assumes this is run from within docker, or a machine with docker running
        const val UNREACHABLE_IPV4 = "180.171.171.171"
        const val UNREACHABLE_IPV6 = "2001:db8::1"
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

    @Test fun testIcmpV4PacketHandling() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val icmpV4EchoPacket = ICMPv4EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
        icmpV4EchoPacket.checksum = icmpV4EchoPacket.computeChecksum(sourceAddress, destinationAddress)
        val ipv4Header =
            Ipv4Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.ICMP.value,
                totalLength =
                    (
                        Ipv4Header.IP4_MIN_HEADER_LENGTH.toInt() +
                            icmpV4EchoPacket.size()
                    ).toUShort(),
            )
        val packet =
            Packet(
                ipv4Header,
                ICMPNextHeaderWrapper(
                    icmpV4EchoPacket,
                    IpType.ICMP.value,
                    "ICMP",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is ICMPNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as ICMPNextHeaderWrapper).icmpHeader is ICMPv4EchoPacket)
    }

    @Test fun testIcmpV6PacketHandling() {
        val sourceAddress = InetAddress.getByName("::1") as Inet6Address
        val destinationAddress = InetAddress.getByName("::1") as Inet6Address
        val icmpV6EchoPacket = ICMPv6EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
        icmpV6EchoPacket.checksum = icmpV6EchoPacket.computeChecksum(sourceAddress, destinationAddress)
        val ipv6Header =
            Ipv6Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.ICMP.value,
                payloadLength = (40 + icmpV6EchoPacket.size()).toUShort(),
            )
        val packet =
            Packet(
                ipv6Header,
                ICMPNextHeaderWrapper(
                    icmpV6EchoPacket,
                    IpType.ICMP.value,
                    "ICMP",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is ICMPNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as ICMPNextHeaderWrapper).icmpHeader is ICMPv6EchoPacket)
    }

    @Test fun icmpV4UnreachableIP() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationAddress = Inet4Address.getByName(UNREACHABLE_IPV4) as Inet4Address
        val icmpV4EchoPacket = ICMPv4EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
        icmpV4EchoPacket.checksum = icmpV4EchoPacket.computeChecksum(sourceAddress, destinationAddress)
        val ipv4Header =
            Ipv4Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.ICMP.value,
                totalLength =
                    (
                        Ipv4Header.IP4_MIN_HEADER_LENGTH.toInt() +
                            icmpV4EchoPacket.size()
                    ).toUShort(),
            )
        val packet =
            Packet(
                ipv4Header,
                ICMPNextHeaderWrapper(
                    icmpV4EchoPacket,
                    IpType.ICMP.value,
                    "ICMP",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is ICMPNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as ICMPNextHeaderWrapper).icmpHeader is ICMPv4DestinationUnreachablePacket)
    }

    @Test fun icmpV6UnreachableIP() {
        val sourceAddress = InetAddress.getByName("::1") as Inet6Address
        val destinationAddress = Inet6Address.getByName(UNREACHABLE_IPV6) as Inet6Address
        val icmpV6EchoPacket = ICMPv6EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
        icmpV6EchoPacket.checksum = icmpV6EchoPacket.computeChecksum(sourceAddress, destinationAddress)
        val ipv6Header =
            Ipv6Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.ICMP.value,
                payloadLength = (40 + icmpV6EchoPacket.size()).toUShort(),
            )
        val packet =
            Packet(
                ipv6Header,
                ICMPNextHeaderWrapper(
                    icmpV6EchoPacket,
                    IpType.ICMP.value,
                    "ICMP",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is ICMPNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as ICMPNextHeaderWrapper).icmpHeader is ICMPv6DestinationUnreachablePacket)
    }
}
