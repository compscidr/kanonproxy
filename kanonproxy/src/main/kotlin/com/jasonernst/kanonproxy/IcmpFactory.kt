package com.jasonernst.kanonproxy

import com.jasonernst.icmp_common.ICMPType
import com.jasonernst.icmp_common.PacketHeaderException
import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachableCodes
import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachablePacket
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachableCodes
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachablePacket
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.ICMPNextHeaderWrapper
import com.jasonernst.knet.transport.TransportHeader
import java.net.InetAddress
import java.nio.ByteBuffer

object IcmpFactory {
    /**
     * Create an ICMP host unreachable packet to send to the VPN client. The source will be the
     * VPN server itself.
     *
     * According to this:
     * https://www.firewall.cx/networking-topics/protocols/icmp-protocol/153-icmp-destination-unreachable.html
     * and wireshark dumps, we must send back the IP header, the transport header, and payload of
     * the packet which generated the ICMP host unreachable.
     *
     * @param sourceAddress source address for the ICMP header
     * @param ipHeader the IP header of the packet which caused the host unreachable
     * @param transportHeader the transport header of the packet which caused the host unreachable
     * @param payload the payload of the packet which caused the host unreachable
     */
    fun createDestinationUnreachable(
        code: ICMPType,
        sourceAddress: InetAddress,
        ipHeader: IpHeader,
        transportHeader: TransportHeader,
        payload: ByteArray,
    ): Packet {
        val protocol =
            when (ipHeader) {
                is Ipv4Header -> IpType.ICMP
                is Ipv6Header -> IpType.IPV6_ICMP
                else -> {
                    throw PacketHeaderException("Unknown IP header type: ${ipHeader::class}")
                }
            }

        val originalRequestBuffer = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
        originalRequestBuffer.put(ipHeader.toByteArray())
        originalRequestBuffer.put(transportHeader.toByteArray())
        originalRequestBuffer.put(payload)
        originalRequestBuffer.rewind()

        val icmpHeader =
            when (ipHeader) {
                is Ipv4Header -> {
                    ICMPv4DestinationUnreachablePacket(code as ICMPv4DestinationUnreachableCodes, 0u, originalRequestBuffer.array())
                }
                is Ipv6Header -> {
                    ICMPv6DestinationUnreachablePacket(code as ICMPv6DestinationUnreachableCodes, 0u, originalRequestBuffer.array())
                }
                else -> {
                    throw PacketHeaderException("Unknown IP header type: ${ipHeader::class}")
                }
            }

        val responseIpHeader =
            IpHeader.createIPHeader(
                sourceAddress,
                ipHeader.sourceAddress,
                protocol,
                (ipHeader.getHeaderLength() + icmpHeader.size().toUShort() + originalRequestBuffer.limit().toUInt()).toInt(),
            )

        return Packet(ipHeader, ICMPNextHeaderWrapper(icmpHeader, protocol.value, "ICMP"), ByteArray(0))
    }
}
