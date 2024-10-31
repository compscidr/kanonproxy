package com.jasonernst.kanonproxy.icmp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v4.IcmpV4EchoPacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6EchoPacket
import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
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
    private val kAnonProxy = KAnonProxy(IcmpLinux, mockk(relaxed = true))

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
        val icmpV4EchoPacket = IcmpV4EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
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
                IcmpNextHeaderWrapper(
                    icmpV4EchoPacket,
                    IpType.ICMP.value,
                    "Icmp",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is IcmpNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as IcmpNextHeaderWrapper).icmpHeader is IcmpV4EchoPacket)
    }

    @Test fun testIcmpV6PacketHandling() {
        val sourceAddress = InetAddress.getByName("::1") as Inet6Address
        val destinationAddress = InetAddress.getByName("::1") as Inet6Address
        val icmpV6EchoPacket = IcmpV6EchoPacket(sourceAddress, destinationAddress, 0u, 1u, 1u, false, "Test Data".toByteArray())
        val ipv6Header =
            Ipv6Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.IPV6_ICMP.value,
                payloadLength = (40 + icmpV6EchoPacket.size()).toUShort(),
            )
        val packet =
            Packet(
                ipv6Header,
                IcmpNextHeaderWrapper(
                    icmpV6EchoPacket,
                    IpType.IPV6_ICMP.value,
                    "IcmpV6",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is IcmpNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as IcmpNextHeaderWrapper).icmpHeader is IcmpV6EchoPacket)
    }

    @Test fun icmpV4UnreachableIP() {
        val sourceAddress = InetAddress.getByName("127.0.0.1") as Inet4Address
        val destinationAddress = Inet4Address.getByName(UNREACHABLE_IPV4) as Inet4Address
        val icmpV4EchoPacket = IcmpV4EchoPacket(0u, 1u, 1u, false, "Test Data".toByteArray())
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
                IcmpNextHeaderWrapper(
                    icmpV4EchoPacket,
                    IpType.ICMP.value,
                    "Icmp",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is IcmpNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as IcmpNextHeaderWrapper).icmpHeader is IcmpV4DestinationUnreachablePacket)
    }

    @Test fun icmpV6UnreachableIP() {
        val sourceAddress = InetAddress.getByName("::1") as Inet6Address
        val destinationAddress = Inet6Address.getByName(UNREACHABLE_IPV6) as Inet6Address
        val icmpV6EchoPacket = IcmpV6EchoPacket(sourceAddress, destinationAddress, 0u, 1u, 1u, false, "Test Data".toByteArray())
        val ipv6Header =
            Ipv6Header(
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                protocol = IpType.IPV6_ICMP.value,
                payloadLength = (40 + icmpV6EchoPacket.size()).toUShort(),
            )
        val packet =
            Packet(
                ipv6Header,
                IcmpNextHeaderWrapper(
                    icmpV6EchoPacket,
                    IpType.IPV6_ICMP.value,
                    "IcmpV6",
                ),
                ByteArray(0),
            )
        kAnonProxy.handlePackets(listOf(packet))
        val response = kAnonProxy.takeResponse()
        assertTrue(response.nextHeaders is IcmpNextHeaderWrapper)
        logger.debug("Got response: {}", response.nextHeaders)
        assertTrue((response.nextHeaders as IcmpNextHeaderWrapper).icmpHeader is IcmpV6DestinationUnreachablePacket)
    }
}
