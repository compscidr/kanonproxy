package com.jasonernst.kanonproxy

import com.jasonernst.icmp_common.ICMP
import com.jasonernst.icmp_common.ICMPHeader
import com.jasonernst.icmp_common.PingResult
import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachableCodes
import com.jasonernst.icmp_common.v4.ICMPv4DestinationUnreachablePacket
import com.jasonernst.icmp_common.v4.ICMPv4EchoPacket
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachableCodes
import com.jasonernst.icmp_common.v6.ICMPv6DestinationUnreachablePacket
import com.jasonernst.icmp_common.v6.ICMPv6EchoPacket
import com.jasonernst.kanonproxy.tcp.TcpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.ICMPNextHeaderWrapper
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.udp.UdpHeader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingDeque

/**
 * @param icmp The ICMP object that will be used to send and receive ICMP packets. Depending on if
 *   this is run on Android or Linux, we should use ICMPLinux or ICMPAndroid.
 */
class KAnonProxy(
    val icmp: ICMP,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val outgoingQueue = LinkedBlockingDeque<Packet>()

    // maps the source IP + port + protocol to a session (need extra work to handle multiple
    // clients (see the handlePackets function)
    // not private for testing
    val sessionTableBySessionKey = ConcurrentHashMap<String, Session>()

    /**
     * Given the list of packets that have been received, this function will
     * determine if an active session is already present for the packet based
     * on the source, destination IP and port + protocol. If a session is not
     * active, a new session will be created and managed by the KAnonProxy.
     *
     * Depending on the type of session, responses may be generated and placed
     * in the response queue which can be retrieved by calling takeResponses(),
     * ideally in a separate thread.
     *
     */
    fun handlePackets(packets: List<Packet>) {
        // TODO: handle case where two+ clients are using the same source, destination IP, port + proto
        //   probably need a UUID, or perhaps the VPN client address if this is used as a VPN server
        //   note: this isn't needed for a TUN/TAP adapter or a packet dumper on Android since there
        //   is only ever one "client". It would be needed for a VPN server, or a multi-hop internet
        //   sharing app on Android.
        packets.forEach { packet ->
            if (packet.nextHeaders is TransportHeader) {
                CoroutineScope(Dispatchers.IO).launch {
                    handleTransportPacket(packet.ipHeader, packet.nextHeaders as TransportHeader, packet.payload)
                }
            } else if (packet.nextHeaders is ICMPNextHeaderWrapper) {
                val icmpPacket = (packet.nextHeaders as ICMPNextHeaderWrapper).icmpHeader
                logger.debug("Got ICMP packet {}", icmpPacket)
                CoroutineScope(Dispatchers.IO).launch {
                    handleICMPPacket(packet.ipHeader, icmpPacket)
                }
            } else {
                logger.error("Unsupported packet type: {}", packet.javaClass)
            }
        }
    }

    private suspend fun handleTransportPacket(
        ipHeader: IpHeader,
        transportHeader: TransportHeader,
        payload: ByteArray,
    ) {
        var isNewSession = false
        val key = Session.getKey(
            ipHeader.sourceAddress,
            transportHeader.sourcePort,
            ipHeader.destinationAddress,
            transportHeader.destinationPort,
            ipHeader.protocol,
        )
        val session =
            sessionTableBySessionKey.getOrPut(key) {
                isNewSession = true
                Session.getSession(
                    ipHeader.sourceAddress,
                    transportHeader.sourcePort,
                    ipHeader.destinationAddress,
                    transportHeader.destinationPort,
                    ipHeader.protocol,
                    outgoingQueue,
                )
            }
        if (isNewSession) {
            logger.info("New session: {} with payload size: {}", session, payload.size)
        }
        when (transportHeader) {
            is UdpHeader -> {
                withContext(Dispatchers.IO) {
                    val bytesWrote = session.channel.write(ByteBuffer.wrap(payload))
                    logger.debug("Wrote {} bytes to session {}", bytesWrote, session)
                }
            }
            is TcpHeader -> {
                handleTcpPacket(session as TcpSession, ipHeader, transportHeader, payload)
            }
            else -> logger.error("Unsupported transport header type: {}", transportHeader.javaClass)
        }
    }

    private suspend fun handleTcpPacket(
        session: TcpSession,
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray
    ) {
        val responsePackets = session.tcpStateMachine.processHeaders(ipHeader, tcpHeader, payload)
        for (packet in responsePackets) {
            outgoingQueue.put(packet)
        }
    }

    /**
     * Handles ICMP packets. For now, this is only ICMP echo requests. All others are ignored.
     *
     * https://datatracker.ietf.org/doc/html/rfc792
     * https://datatracker.ietf.org/doc/html/rfc4443
     *
     * According to the spec, if the ping fails, we should send an ICMP NETWORK_UNREACHABLE for
     * IPv4 or a NO_ROUTE_TO_DESTINATION for IPv6.
     *
     * When a failure occurs, we need to copy the original IP header + ICMP header into the payload
     * of the ICMP response.
     */
    private suspend fun handleICMPPacket(
        ipHeader: IpHeader,
        icmpPacket: ICMPHeader,
    ) {
        if (icmpPacket is ICMPv4EchoPacket || icmpPacket is ICMPv6EchoPacket) {
            val result = icmp.ping(ipHeader.destinationAddress)
            val icmpResponse =
                if (result is PingResult.Success) {
                    if (icmpPacket is ICMPv4EchoPacket) {
                        ICMPv4EchoPacket(0u, icmpPacket.id, icmpPacket.sequence, true, icmpPacket.data)
                    } else {
                        icmpPacket as ICMPv6EchoPacket
                        ICMPv6EchoPacket(0u, icmpPacket.id, icmpPacket.sequence, true, icmpPacket.data)
                    }
                } else {
                    if (icmpPacket is ICMPv4EchoPacket) {
                        val payload = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
                        payload.put(ipHeader.toByteArray())
                        payload.put(icmpPacket.toByteArray())
                        ICMPv4DestinationUnreachablePacket(ICMPv4DestinationUnreachableCodes.NETWORK_UNREACHABLE, data = payload.array())
                    } else {
                        val payload = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
                        payload.put(ipHeader.toByteArray())
                        payload.put(icmpPacket.toByteArray())
                        ICMPv6DestinationUnreachablePacket(
                            ICMPv6DestinationUnreachableCodes.NO_ROUTE_TO_DESTINATION,
                            data = payload.array(),
                        )
                    }
                }

            val ipResponse =
                if (icmpPacket is ICMPv4EchoPacket) {
                    Ipv4Header(
                        sourceAddress = ipHeader.destinationAddress as Inet4Address,
                        destinationAddress = ipHeader.sourceAddress as Inet4Address,
                        protocol = ipHeader.protocol,
                        totalLength =
                            (
                                ipHeader.getHeaderLength() +
                                    icmpResponse.size().toUInt()
                            ).toUShort(),
                    )
                } else {
                    Ipv6Header(
                        sourceAddress = ipHeader.destinationAddress as Inet6Address,
                        destinationAddress = ipHeader.sourceAddress as Inet6Address,
                        protocol = ipHeader.protocol,
                        payloadLength =
                            (
                                ipHeader.getHeaderLength() +
                                    icmpResponse.size().toUInt()
                            ).toUShort(),
                    )
                }
            outgoingQueue.put(Packet(ipResponse, ICMPNextHeaderWrapper(icmpResponse, ipHeader.protocol, "ICMP"), ByteArray(0)))
        } else {
            logger.error("Ignoring Unsupported ICMP packet type: {}", icmpPacket.javaClass)
        }
    }

    /**
     * This function will block until a packet is available.
     */
    fun takeResponse(): Packet = outgoingQueue.take()
}
