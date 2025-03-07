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
import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession
import com.jasonernst.kanonproxy.tcp.TcpHeaderFactory.createRstPacket
import com.jasonernst.kanonproxy.tcp.TcpStateMachine.Companion.G
import com.jasonernst.kanonproxy.tcp.TransmissionControlBlock
import com.jasonernst.kanonproxy.udp.UdpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.v4.Ipv4Header
import com.jasonernst.knet.network.ip.v6.Ipv6Header
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.jetbrains.annotations.TestOnly
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean

/**
 * @param icmp The Icmp object that will be used to send and receive Icmp packets. Depending on if
 *   this is run on Android or Linux, we should use IcmpLinux or IcmpAndroid.
 */
class KAnonProxy(
    val icmp: Icmp,
    val protector: VpnProtector = DummyProtector,
    val trafficAccounting: TrafficAccounting = DummyTrafficAccount,
) : SessionManager {
    private val logger = LoggerFactory.getLogger(javaClass)

    // We use a map of the client ip address + port (InetSocketAddress) to a queue of packets so that we don't have
    // to worry about multiple clients using the same source IP + port + protocol. It also prevents one client from
    // blocking another
    private val outgoingQueues = ConcurrentHashMap<InetSocketAddress, LinkedBlockingDeque<Packet>>()
    private val incomingQueue = LinkedBlockingDeque<Pair<Packet, InetSocketAddress?>>()
    val sessionTablesBySessionKey = ConcurrentHashMap<InetSocketAddress, ConcurrentHashMap<String, Session>>()

    private val isRunning = AtomicBoolean(false)
    private lateinit var maintenanceJob: CompletableJob // https://stackoverflow.com/a/63407811
    private lateinit var maintenanceScope: CoroutineScope
    private lateinit var incomingQueueJob: CompletableJob
    private lateinit var incomingQueueScope: CoroutineScope

    companion object {
        const val STALE_SESSION_MS = 5000L
        const val DEFAULT_PORT = 8080
    }

    fun start() {
        if (isRunning.get()) {
            logger.warn("KAnonProxy is already running")
            return
        }
        logger.debug("Starting KAnonProxy")
        isRunning.set(true)
        maintenanceJob = SupervisorJob()
        maintenanceScope = CoroutineScope(Dispatchers.IO + maintenanceJob)
        maintenanceScope.launch {
            sessionMaintenanceThread()
        }
        incomingQueueJob = SupervisorJob()
        incomingQueueScope = CoroutineScope(Dispatchers.IO + incomingQueueJob)
        incomingQueueScope.launch {
            packetHandler()
        }
        logger.debug("KAnonProxy started")
    }

    private fun packetHandler() {
        Thread.currentThread().name = "Kanon Packethandler"
        logger.debug("Packet handler is started")
        logger.debug("Session table size: ${sessionTablesBySessionKey.size}")
        logger.debug("Incoming queue size: ${incomingQueue.size}")
        logger.debug("Outgoing queues size: ${outgoingQueues.size}")
        while (isRunning.get()) {
            val queueEntry = incomingQueue.take()
            val packet = queueEntry.first
            if (packet == SentinelPacket) {
                logger.debug("Received sentinel packet, stopping packet handler")
                break
            }
            if (isRunning.get().not()) {
                logger.debug("Proxy shutting down, skipping packet")
                break
            }
            val clientAddress = queueEntry.second
            if (clientAddress == null) {
                logger.error("Client address is null, skipping packet")
                continue
            }
            handlePacket(packet, clientAddress)
        }
        logger.debug("Packet handler is stopped")
        incomingQueueJob.complete()
    }

    /**
     * Enqueue packets to be processed by the KAnonProxy. This function is non-blocking.
     */
    override fun handlePackets(
        packets: List<Packet>,
        clientAddress: InetSocketAddress,
    ) {
        for (packet in packets) {
            incomingQueue.add(Pair(packet, clientAddress))
        }
    }

    /**
     * Given the current packet to be processed, this function will
     * determine if an active session is already present for the packet based
     * on the source, destination IP and port + protocol. If a session is not
     * active, a new session will be created and managed by the KAnonProxy.
     *
     * Depending on the type of session, responses may be generated and placed
     * in the response queue which can be retrieved by calling takeResponses(),
     * ideally in a separate thread.
     *
     * // TODO: handle case where two+ clients are using the same source, destination IP, port + proto
     *         //   probably need a UUID, or perhaps the VPN client address if this is used as a VPN server
     *         //   note: this isn't needed for a TUN/TAP adapter or a packet dumper on Android since there
     *         //   is only ever one "client". It would be needed for a VPN server, or a multi-hop internet
     *         //   sharing app on Android.
     */
    private fun handlePacket(
        packet: Packet,
        clientAddress: InetSocketAddress,
    ) {
        if (!isRunning.get()) {
            logger.warn("KAnonProxy is not running, ignoring packets")
            return
        }

        if (packet.ipHeader == null || packet.nextHeaders == null || packet.payload == null) {
            logger.debug("missing header(s) or payload, skipping packet")
            return
        }
        when (packet.nextHeaders) {
            is TransportHeader -> {
                handleTransportPacket(packet.ipHeader!!, packet.nextHeaders as TransportHeader, packet.payload!!, clientAddress)
            }

            is IcmpNextHeaderWrapper -> {
                val icmpPacket = (packet.nextHeaders as IcmpNextHeaderWrapper).icmpHeader
                logger.debug("Got Icmp packet {}", icmpPacket)
                handleIcmpPacket(packet.ipHeader!!, icmpPacket, clientAddress)
            }

            else -> {
                logger.error("Unsupported packet type: {}", packet.javaClass)
            }
        }
    }

    private fun handleTransportPacket(
        ipHeader: IpHeader,
        transportHeader: TransportHeader,
        payload: ByteArray,
        clientAddress: InetSocketAddress,
    ) {
        val sessionTableBySessionKey =
            sessionTablesBySessionKey.getOrPut(clientAddress) {
                logger.debug("New session table for client: {}", clientAddress)
                ConcurrentHashMap()
            }
        val outgoingQueue =
            outgoingQueues.getOrPut(clientAddress) {
                logger.warn("New outgoing queue for client: {}", clientAddress)
                LinkedBlockingDeque()
            }
        var isNewSession = false
        val key =
            Session.getKey(
                ipHeader.sourceAddress,
                transportHeader.sourcePort,
                ipHeader.destinationAddress,
                transportHeader.destinationPort,
                ipHeader.protocol,
            )
        try {
            val session =
                sessionTableBySessionKey.getOrPut(key) {
                    isNewSession = true
                    Session.getNewSession(
                        ipHeader,
                        transportHeader,
                        payload,
                        outgoingQueue,
                        protector,
                        this,
                        clientAddress,
                        trafficAccounting,
                    )
                }
            if (isNewSession) {
                logger.info("New session: {} with payload size: {}", session, payload.size)
            } else {
                session.lastHeard = System.currentTimeMillis()
            }
            session.incomingQueue.add(Packet(ipHeader, transportHeader, payload))
        } catch (e: IllegalArgumentException) {
            logger.warn("Got a non SYN packet $transportHeader when we had no session saved, sending RST")
            outgoingQueue.put(createRstPacket(ipHeader, transportHeader as TcpHeader, TransmissionControlBlock()))
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
    private fun handleIcmpPacket(
        ipHeader: IpHeader,
        icmpPacket: IcmpHeader,
        clientAddress: InetSocketAddress,
    ) {
        val outgoingQueue =
            outgoingQueues.getOrPut(clientAddress) {
                LinkedBlockingDeque()
            }
        logger.debug("outgoing queue: $outgoingQueue")
        if (icmpPacket is IcmpV4EchoPacket || icmpPacket is IcmpV6EchoPacket) {
            val result =
                runBlocking {
                    return@runBlocking icmp.ping(ipHeader.destinationAddress)
                }
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
     * This function will block until a packet is available. So for multiple clients, this should be called in a
     * separate thread for each client.
     */
    fun takeResponse(clientAddress: InetSocketAddress): Packet {
        val outgoingQueue =
            outgoingQueues.getOrPut(clientAddress) {
                logger.warn("No outgoing queue for client when taking response: {}", clientAddress)
                LinkedBlockingDeque()
            }
        if (!isRunning.get()) {
            logger.warn("KAnonProxy is not running, ignoring packets")
            return SentinelPacket
        }
        val packet = outgoingQueue.take()
        // logger.debug("Proxy packets remaining: {}", outgoingQueue.size)
        return packet
    }

    private suspend fun sessionMaintenanceThread() {
        Thread.currentThread().name = "Session maintenance thread"
        logger.debug("Session maintenance thread is started")
        while (isRunning.get()) {
            val startTime = System.currentTimeMillis()
            for (sessionTableBySessionKey in sessionTablesBySessionKey.values) {
                for (session in sessionTableBySessionKey.values) {
                    if (session.lastHeard < System.currentTimeMillis() - STALE_SESSION_MS) {
                        if (session is UdpSession) {
                            logger.warn("Session {} is stale, closing", session)
                            withContext(Dispatchers.IO) {
                                session.close(true)
                            }
                            continue
                        }
                    }
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
        maintenanceJob.complete()
        logger.warn("Session maintenance thread is (stop)ped")
    }

    fun haveSessionForClient(
        clientAddress: InetSocketAddress,
        key: String,
    ): Boolean = sessionTablesBySessionKey[clientAddress]?.containsKey(key) == true

    fun flushQueue(clientAddress: InetSocketAddress) {
        val outgoingQueue =
            outgoingQueues.getOrPut(clientAddress) {
                logger.warn("No outgoing queue for client when flushing queue: {}", clientAddress)
                LinkedBlockingDeque()
            }
        outgoingQueue.clear()
    }

    override fun removeSessionByClientAddress(clientAddress: InetSocketAddress) {
        sessionTablesBySessionKey.remove(clientAddress)
        outgoingQueues.remove(clientAddress)
        val outgoingQueue = outgoingQueues[clientAddress]
        if (outgoingQueue != null) {
            outgoingQueue.put(SentinelPacket)
            outgoingQueues.remove(clientAddress)
        }
        for (entry in incomingQueue) {
            if (entry.second == clientAddress) {
                incomingQueue.remove(entry)
            }
        }
    }

    override fun removeSession(session: Session) {
        logger.debug("Removing session: {}", session)
        val sessionTableBySessionKey = sessionTablesBySessionKey[session.clientAddress] ?: return
        sessionTableBySessionKey.remove(session.getKey())

        if (sessionTableBySessionKey.isEmpty()) {
            logger.debug("No more sessions for client: {}, removing from session table", session.clientAddress)
            sessionTablesBySessionKey.remove(session.clientAddress)
            val outgoingQueue =
                outgoingQueues.getOrPut(session.clientAddress) {
                    logger.warn("No outgoing queue for client when removing session queue: {}", session.clientAddress)
                    LinkedBlockingDeque()
                }
            outgoingQueue.put(SentinelPacket)
            outgoingQueues.remove(session.clientAddress)
        } else {
            logger.debug("Still have ${sessionTableBySessionKey.size} sessions")
            for (entry in sessionTableBySessionKey) {
                val session = entry.value
                val state =
                    if (session is AnonymousTcpSession) {
                        session.tcpStateMachine.tcpState.value
                            .toString()
                    } else {
                        ""
                    }
                logger.debug("  $state ${entry.key}")
            }
        }
    }

    override fun isRunning(): Boolean = isRunning.get()

    fun stop() {
        logger.debug("Stopping KAnonProxy")
        isRunning.set(false)

        // stopping handling of incoming packets
        incomingQueue.put(Pair(SentinelPacket, null))

        runBlocking {
            logger.debug("Waiting for maintenance job to finish")
            maintenanceJob.cancelAndJoin()
            logger.debug("maintenance job finished")
            logger.debug("Waiting for incomingQueue job to finish")
            incomingQueueJob.cancelAndJoin()
            logger.debug("incoming queue job finished")
        }

        for (sessionTable in sessionTablesBySessionKey.values) {
            for (session in sessionTable.values) {
                logger.debug("Closing session: $session")
                session.close()
                logger.debug("Session closed: $session")
            }
            sessionTable.clear()
            logger.debug("Sessions cleared")
        }
        for (queue in outgoingQueues.values) {
            queue.clear()
        }
        logger.debug("outgoing queues cleared")
        sessionTablesBySessionKey.clear()
        outgoingQueues.clear()
        incomingQueue.clear()
        logger.debug("KAnonProxy stopped")
    }

    @TestOnly
    fun disconnectClient(clientAddress: InetSocketAddress) {
        val outgoingQueue = outgoingQueues[clientAddress]
        outgoingQueue?.add(SentinelPacket)
    }
}
