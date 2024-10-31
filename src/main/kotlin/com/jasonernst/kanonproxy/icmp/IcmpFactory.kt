package com.jasonernst.kanonproxy.icmp

import com.jasonernst.icmp.common.IcmpType
import com.jasonernst.icmp.common.PacketHeaderException
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import com.jasonernst.knet.transport.TransportHeader
import java.net.Inet6Address
import java.net.InetAddress
import java.nio.ByteBuffer

object IcmpFactory {
    /**
     * Create an Icmp host unreachable packet to send to the VPN client. The source will be the
     * VPN server itself.
     *
     * According to this:
     * https://www.firewall.cx/networking-topics/protocols/icmp-protocol/153-icmp-destination-unreachable.html
     * and wireshark dumps, we must send back the IP header, the transport header, and payload of
     * the packet which generated the Icmp host unreachable.
     *
     * @param sourceAddress source address for the Icmp header
     * @param ipHeader the IP header of the packet which caused the host unreachable
     * @param transportHeader the transport header of the packet which caused the host unreachable
     *  (only the first 64-bits of it are used)
     *
     */
    fun createDestinationUnreachable(
        code: IcmpType,
        sourceAddress: InetAddress,
        ipHeader: IpHeader,
        transportHeader: TransportHeader,
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

        val originalTransportBuffer = transportHeader.toByteArray()
        val reducedTransportBuffer = ByteArray(8) // RFC792 and RFC4443 say to include the first 64-bits of anything after the IP header
        System.arraycopy(originalTransportBuffer, 0, reducedTransportBuffer, 0, 8)
        originalRequestBuffer.put(reducedTransportBuffer)
        originalRequestBuffer.rewind()

        val icmpHeader =
            when (ipHeader) {
                is Ipv4Header -> {
                    IcmpV4DestinationUnreachablePacket(code as IcmpV4DestinationUnreachableCodes, 0u, originalRequestBuffer.array())
                }
                is Ipv6Header -> {
                    IcmpV6DestinationUnreachablePacket(
                        sourceAddress as Inet6Address,
                        ipHeader.sourceAddress,
                        code as IcmpV6DestinationUnreachableCodes,
                        0u,
                        originalRequestBuffer.array(),
                    )
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

        return Packet(responseIpHeader, IcmpNextHeaderWrapper(icmpHeader, protocol.value, "Icmp"), ByteArray(0))
    }
}
