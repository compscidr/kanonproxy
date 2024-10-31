package com.jasonernst.kanonproxy

import com.jasonernst.icmp.common.Icmp
import com.jasonernst.icmp.common.IcmpHeader
import com.jasonernst.icmp.common.PingResult
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v4.IcmpV4EchoPacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6EchoPacket
import com.jasonernst.kanonproxy.icmp.IcmpFactory
import com.jasonernst.kanonproxy.tcp.TcpSession
import com.jasonernst.kanonproxy.tcp.TcpState
import com.jasonernst.kanonproxy.tcp.TcpStateMachine.Companion.G
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.knet.transport.udp.UdpHeader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin

/**
 * @param icmp The Icmp object that will be used to send and receive Icmp packets. Depending on if
 *   this is run on Android or Linux, we should use IcmpLinux or IcmpAndroid.
 */
class KAnonProxy(
    val icmp: Icmp,
    val protector: VpnProtector = DummyProtector,
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    // todo: we need a per-session queue, not a global queue, or we'll have collisions on the take calls
    private val outgoingQueue = LinkedBlockingDeque<Packet>()

    // maps the source IP + port + protocol to a session (need extra work to handle multiple
    // clients (see the handlePackets function)
    // not private for testing
    val sessionTableBySessionKey = ConcurrentHashMap<String, Session>()

    private val isRunning = AtomicBoolean(false)
    private var maintenanceJob = SupervisorJob() // https://stackoverflow.com/a/63407811
    private val maintenanceScope = CoroutineScope(Dispatchers.IO + maintenanceJob)

    companion object {
        const val STALE_SESSION_MS = 5000L
    }

    fun start() {
        if (isRunning.get()) {
            logger.warn("KAnonProxy is already running")
            return
        }
        isRunning.set(true)
        maintenanceScope.launch {
            Thread.currentThread().name = "KanonProxy Maintenance Thread"
            sessionMaintenanceThread()
        }
        logger.debug("KAnonProxy started")
    }

    fun stop() {
        logger.debug("Stopping KAnonProxy")
        isRunning.set(false)
        runBlocking {
            maintenanceJob.cancelAndJoin()
        }
        outgoingQueue.clear()
        sessionTableBySessionKey.clear()
        logger.debug("KAnonProxy stopped")
    }

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
        if (!isRunning.get()) {
            logger.warn("KAnonProxy is not running, ignoring packets")
            return
        }
        // TODO: handle case where two+ clients are using the same source, destination IP, port + proto
        //   probably need a UUID, or perhaps the VPN client address if this is used as a VPN server
        //   note: this isn't needed for a TUN/TAP adapter or a packet dumper on Android since there
        //   is only ever one "client". It would be needed for a VPN server, or a multi-hop internet
        //   sharing app on Android.
        packets.forEach { packet ->
            if (packet.ipHeader == null || packet.nextHeaders == null || packet.payload == null) {
                logger.debug("missing header(s) or payload, skipping packet")
                return@forEach
            }
            when (packet.nextHeaders) {
                is TransportHeader -> {
                    CoroutineScope(Dispatchers.IO).launch {
                        Thread.currentThread().name = "KanonProxy Transport Packet Handler"
                        handleTransportPacket(packet.ipHeader!!, packet.nextHeaders as TransportHeader, packet.payload!!)
                    }
                }

                is IcmpNextHeaderWrapper -> {
                    val icmpPacket = (packet.nextHeaders as IcmpNextHeaderWrapper).icmpHeader
                    logger.debug("Got Icmp packet {}", icmpPacket)
                    CoroutineScope(Dispatchers.IO).launch {
                        Thread.currentThread().name = "KanonProxy Icmp Packet Handler"
                        handleIcmpPacket(packet.ipHeader!!, icmpPacket)
                    }
                }

                else -> {
                    logger.error("Unsupported packet type: {}", packet.javaClass)
                }
            }
        }
    }

    private suspend fun handleTransportPacket(
        ipHeader: IpHeader,
        transportHeader: TransportHeader,
        payload: ByteArray,
    ) {
        var isNewSession = false
        val key =
            Session.getKey(
                ipHeader.sourceAddress,
                transportHeader.sourcePort,
                ipHeader.destinationAddress,
                transportHeader.destinationPort,
                ipHeader.protocol,
            )
        val session =
            try {
                sessionTableBySessionKey.getOrPut(key) {
                    isNewSession = true
                    Session.getSession(
                        ipHeader.sourceAddress,
                        transportHeader.sourcePort,
                        ipHeader.destinationAddress,
                        transportHeader.destinationPort,
                        ipHeader.protocol,
                        outgoingQueue,
                        protector,
                    )
                }
            } catch (e: Exception) {
                // this should catch any exceptions trying to make the connection for a TCP or UDP session
                logger.error("Error creating session: ${e.message}")
                val code =
                    when (ipHeader) {
                        is Ipv4Header -> IcmpV4DestinationUnreachableCodes.HOST_UNREACHABLE
                        is Ipv6Header -> IcmpV6DestinationUnreachableCodes.ADDRESS_UNREACHABLE
                        else -> throw IllegalArgumentException("Unknown IP protocol: " + ipHeader::class.java.simpleName)
                    }
                val mtu =
                    if (ipHeader is Ipv4Header) {
                        TcpOptionMaximumSegmentSize.defaultIpv4MSS
                    } else {
                        TcpOptionMaximumSegmentSize.defaultIpv6MSS
                    }
                val response =
                    IcmpFactory.createDestinationUnreachable(
                        code,
                        // source address for the Icmp header, send it back to the client as if its the clients own OS
                        // telling it that its unreachable
                        ipHeader.sourceAddress,
                        ipHeader,
                        transportHeader,
                        payload,
                        mtu.toInt(),
                    )
                outgoingQueue.add(response)
                return
            }
        if (isNewSession) {
            logger.info("New session: {} with payload size: {}", session, payload.size)
        } else {
            session.lastHeard = System.currentTimeMillis()
        }
        when (transportHeader) {
            is UdpHeader -> {
                withContext(Dispatchers.IO) {
                    try {
                        val bytesWrote = session.channel.write(ByteBuffer.wrap(payload))
                        logger.debug("Wrote {} bytes to session {}", bytesWrote, session)
                    } catch (e: Exception) {
                        logger.error("Error writing to UDP channel: $e")
                    }
                }
            }
            is TcpHeader -> {
                handleTcpPacket(session as TcpSession, ipHeader, transportHeader, payload)
                if (session.tcpStateMachine.tcpState.value == TcpState.CLOSED) {
                    logger.debug("Tcp session is closed, removing from session table, {}", session)
                    sessionTableBySessionKey.remove(key)

                    // todo: we need this to be per-session at some point
                    outgoingQueue.put(SentinelPacket)
                }
            }
            else -> logger.error("Unsupported transport header type: {}", transportHeader.javaClass)
        }
    }

    private suspend fun handleTcpPacket(
        session: TcpSession,
        ipHeader: IpHeader,
        tcpHeader: TcpHeader,
        payload: ByteArray,
    ) {
        val responsePackets = session.tcpStateMachine.processHeaders(ipHeader, tcpHeader, payload)
        for (packet in responsePackets) {
            outgoingQueue.put(packet)
        }
    }

    /**
     * Handles Icmp packets. For now, this is only Icmp echo requests. All others are ignored.
     *
     * https://datatracker.ietf.org/doc/html/rfc792
     * https://datatracker.ietf.org/doc/html/rfc4443
     *
     * According to the spec, if the ping fails, we should send an Icmp NETWORK_UNREACHABLE for
     * IPv4 or a NO_ROUTE_TO_DESTINATION for IPv6.
     *
     * When a failure occurs, we need to copy the original IP header + Icmp header into the payload
     * of the Icmp response.
     */
    private suspend fun handleIcmpPacket(
        ipHeader: IpHeader,
        icmpPacket: IcmpHeader,
    ) {
        if (icmpPacket is IcmpV4EchoPacket || icmpPacket is IcmpV6EchoPacket) {
            val result = icmp.ping(ipHeader.destinationAddress)
            val icmpResponse =
                if (result is PingResult.Success) {
                    if (icmpPacket is IcmpV4EchoPacket) {
                        IcmpV4EchoPacket(0u, icmpPacket.id, icmpPacket.sequence, true, icmpPacket.data)
                    } else {
                        icmpPacket as IcmpV6EchoPacket
                        IcmpV6EchoPacket(
                            ipHeader.destinationAddress as Inet6Address,
                            ipHeader.sourceAddress as Inet6Address,
                            0u,
                            icmpPacket.id,
                            icmpPacket.sequence,
                            true,
                            icmpPacket.data,
                        )
                    }
                } else {
                    if (icmpPacket is IcmpV4EchoPacket) {
                        val payload = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
                        payload.put(ipHeader.toByteArray())
                        payload.put(icmpPacket.toByteArray())
                        IcmpV4DestinationUnreachablePacket(IcmpV4DestinationUnreachableCodes.NETWORK_UNREACHABLE, data = payload.array())
                    } else {
                        val payload = ByteBuffer.allocate(ipHeader.getTotalLength().toInt())
                        payload.put(ipHeader.toByteArray())
                        payload.put(icmpPacket.toByteArray())
                        IcmpV6DestinationUnreachablePacket(
                            ipHeader.destinationAddress as Inet6Address,
                            ipHeader.sourceAddress as Inet6Address,
                            IcmpV6DestinationUnreachableCodes.NO_ROUTE_TO_DESTINATION,
                            data = payload.array(),
                        )
                    }
                }

            val ipResponse =
                if (icmpPacket is IcmpV4EchoPacket) {
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
            outgoingQueue.put(Packet(ipResponse, IcmpNextHeaderWrapper(icmpResponse, ipHeader.protocol, "Icmp"), ByteArray(0)))
        } else {
            logger.error("Ignoring Unsupported Icmp packet type: {}", icmpPacket.javaClass)
        }
    }

    /**
     * This function will block until a packet is available.
     */
    fun takeResponse(): Packet {
        if (!isRunning.get()) {
            logger.warn("KAnonProxy is not running, ignoring packets")
            return SentinelPacket
        }
        return outgoingQueue.take()
    }

    private suspend fun sessionMaintenanceThread() {
        while (isRunning.get()) {
            val startTime = System.currentTimeMillis()
            for (session in sessionTableBySessionKey.values) {
                if (session.lastHeard < System.currentTimeMillis() - STALE_SESSION_MS) {
                    logger.warn("Session {} is stale, removing", session)
                    try {
                        session.channel.close()
                    } catch (e: Exception) {
                        logger.error("Error closing channel: ${e.message}")
                    }
                    sessionTableBySessionKey.remove(session.getKey())
                    continue
                }
                if (session is TcpSession) {
                    processRetransmits(session)
                    processReverseAcks(session)
                }
            }

            val endTime = System.currentTimeMillis()
            val elapsed = endTime - startTime
            val idealSleep = (G * 1000).toLong()

            // if it took longer than one clock resolution, just keep processing
            // otherwise sleep for the difference
            if (idealSleep - elapsed > 0) {
                delay(idealSleep - elapsed)
            } else {
                logger.warn("Retransmit thread took longer than one clock resolution")
            }
        }
    }

    private suspend fun processRetransmits(session: TcpSession) {
        session.tcpStateMachine.tcbMutex.withLock {
            if (session.tcpStateMachine.tcpState.value == TcpState.CLOSED) {
                logger.error("Trying to process retransmit for a CLOSED session")
                sessionTableBySessionKey.remove(session.getKey())
                return
            }
            val retransmits = session.tcpStateMachine.processTimeouts(session)
            for (retransmit in retransmits) {
                logger.debug("Queuing retransmitting packet: $retransmit")
                outgoingQueue.put(retransmit)
            }
        }
    }

    private suspend fun processReverseAcks(session: TcpSession) {
        session.tcpStateMachine.tcbMutex.withLock {
            if (session.tcpStateMachine.tcpState.value == TcpState.CLOSED) {
                logger.error("Trying to process reverse ACKs for a CLOSED session")
                sessionTableBySessionKey.remove(session.getKey())
                return
            }
            val reverseAcks = session.tcpStateMachine.checkForReverseAcks(session)
            for (reverseAck in reverseAcks) {
                logger.warn(
                    "Waited over 500 ms for reverse traffic, enqueuing ACK " +
                        "${(reverseAck.nextHeaders as TcpHeader).acknowledgementNumber}",
                )
                outgoingQueue.put(reverseAck)
            }
        }
    }

    // todo: when we have per session queues, we will need a parameter like a key
    fun disconnectSession() {
        outgoingQueue.put(SentinelPacket)
    }
}
