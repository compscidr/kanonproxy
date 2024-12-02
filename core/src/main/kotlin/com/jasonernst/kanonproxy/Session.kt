package com.jasonernst.kanonproxy

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.kanonproxy.KAnonProxy.Companion.STALE_SESSION_MS
import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession
import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession.Companion.CONNECTION_POLL_MS
import com.jasonernst.kanonproxy.udp.UdpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.icmp.IcmpFactory
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.nio.channels.CancelledKeyException
import java.nio.channels.ClosedSelectorException
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.channels.spi.AbstractSelectableChannel
import java.util.LinkedList
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

abstract class Session(
    var initialIpHeader: IpHeader?,
    var initialTransportHeader: TransportHeader?,
    var initialPayload: ByteArray?,
    val returnQueue: LinkedBlockingDeque<Packet>,
    val protector: VpnProtector,
    val sessionManager: SessionManager,
    val clientAddress: InetSocketAddress,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    abstract val channel: ByteChannel
    val outgoingToInternet = BidirectionalByteChannel()
    protected val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    var lastHeard = System.currentTimeMillis()
    private val outgoingJob = SupervisorJob() // https://stackoverflow.com/a/63407811
    protected val outgoingScope = CoroutineScope(Dispatchers.IO + outgoingJob)

    val incomingQueue = LinkedBlockingDeque<Packet>()
    private val incomingJob = SupervisorJob()
    private val incomingScope = CoroutineScope(Dispatchers.IO + incomingJob)
    private val isRunning = AtomicBoolean(true)

    private val channelJob = SupervisorJob()
    private val channelScope = CoroutineScope(Dispatchers.IO + channelJob)

    val selector: Selector = Selector.open()
    val changeRequests = LinkedList<ChangeRequest>()

    companion object {
        fun getKey(
            sourceIp: InetAddress,
            sourcePort: UShort,
            destinationIp: InetAddress,
            destinationPort: UShort,
            protocol: UByte,
        ): String = "$sourceIp:$sourcePort:$destinationIp:$destinationPort:$protocol"

        /**
         * Depending on the protocol, returns either a UDP or TCP session
         */
        fun getSession(
            initialIPHeader: IpHeader,
            initialTransportHeader: TransportHeader,
            initialPayload: ByteArray,
            returnQueue: LinkedBlockingDeque<Packet>,
            protector: VpnProtector,
            sessionManager: SessionManager,
            clientAddress: InetSocketAddress,
        ): Session =
            when (initialIPHeader.protocol) {
                IpType.UDP.value -> {
                    UdpSession(
                        initialIPHeader,
                        initialTransportHeader,
                        initialPayload,
                        returnQueue,
                        protector,
                        sessionManager,
                        clientAddress,
                    )
                }
                IpType.TCP.value -> {
                    AnonymousTcpSession(
                        initialIPHeader,
                        initialTransportHeader,
                        initialPayload,
                        returnQueue,
                        protector,
                        sessionManager,
                        clientAddress,
                    )
                }
                else -> {
                    throw IllegalArgumentException("Unsupported protocol for session")
                }
            }
    }

    open fun getKey(): String = getKey(getSourceAddress(), getSourcePort(), getDestinationAddress(), getDestinationPort(), getProtocol())

    override fun toString(): String =
        "Session(clientAddress='$clientAddress' sourceAddress='${getSourceAddress()}', sourcePort=${getSourcePort()}, destinationAddress='${getDestinationAddress()}', destinationPort=${getDestinationPort()}, protocol=${getProtocol()})"

    fun readyToWrite() {
        if (channel is BidirectionalByteChannel) {
            return
        }
        synchronized(changeRequests) {
            changeRequests.add(ChangeRequest(channel as AbstractSelectableChannel, ChangeRequest.REGISTER, SelectionKey.OP_WRITE))
        }
        selector.wakeup()
    }

    fun startSelector() {
        channelScope.launch {
            Thread.currentThread().name = "Channel scope: ${getKey()}"
            while (isRunning.get()) {
                try {
                    // Process any pending changes
                    synchronized(changeRequests) {
                        for (changeRequest in changeRequests) {
                            when (changeRequest.type) {
                                ChangeRequest.REGISTER -> {
                                    // logger.debug("Processing REGISTER")
                                    changeRequest.channel.register(selector, changeRequest.ops)
                                }
                                ChangeRequest.CHANGE_OPS -> {
                                    // logger.debug("Processing CHANGE_OPS")
                                    val key = changeRequest.channel.keyFor(selector)
                                    key.interestOps(changeRequest.ops)
                                }
                            }
                        }
                        changeRequests.clear()
                    }
                    // logger.warn("Waiting for SELECT")
                    // lock so we don't add or remove from the selector while we're selecting
                    val session = this@Session
                    val numKeys =
                        if (session is AnonymousTcpSession) {
                            if (session.isConnecting.get()) {
                                selector.select(CONNECTION_POLL_MS)
                            } else {
                                selector.select()
                            }
                        } else {
                            selector.select()
                        }
                    if (numKeys > 0) {
                        // logger.warn("SELECT RETURNED: $numKeys")
                    } else {
                        if (session is AnonymousTcpSession && session.isConnecting.get()) {
                            val currentTime = System.currentTimeMillis()
                            val difference = currentTime - session.connectTime
                            if (difference > STALE_SESSION_MS) {
                                val error = "Timed trying to reach remote out on TCP connect"
                                logger.error(error)
                                handleExceptionOnRemoteChannel(Exception(error))
                            }
                        }
                    }
                } catch (e: Exception) {
                    logger.warn("Exception on select, probably shutting down: $e")
                    break
                }

                try {
                    val selectedKeys = selector.selectedKeys()
                    if (selectedKeys.size > 0) {
                        // logger.warn("SELECT: $selectedKeys")
                    }
                    val keyStream = selectedKeys.parallelStream()
                    keyStream
                        .forEach {
                            if (!it.isValid) {
                                logger.error("INVALID KEY!!!!! $this@Session")
                            }
                            if (it.isWritable && it.isValid) {
                                val available = outgoingToInternet.available()
                                if (available > 0) {
                                    val buff = ByteBuffer.allocate(available)
                                    outgoingToInternet.read(buff)
                                    buff.flip()
                                    flushToRealChannel(buff)
                                }
                                it.interestOps(SelectionKey.OP_READ)
                            }
                            if (it.isReadable && it.isValid) {
                                if (!read()) {
                                    it.interestOps(SelectionKey.OP_READ.inv())
                                }
                            }
                            if (it.isConnectable) {
                                val socketChannel = it.channel() as SocketChannel
                                // logger.debug("Tcp connectable, trying to finish connection to ${socketChannel.remoteAddress}")
                                if (socketChannel.isConnectionPending) {
                                    try {
                                        val result = socketChannel.finishConnect()
                                        if (result) {
                                            logger.debug("Tcp connection successful")
                                            it.interestOps(SelectionKey.OP_READ)
                                            startIncomingHandling()
                                        } else {
                                            logger.debug("Finishing connection, still in progress")
                                            // will retry again when the selector wakes up
                                        }
                                    } catch (e: Exception) {
                                        handleExceptionOnRemoteChannel(e)
                                    }
                                }
                            }
                        }
                    selectedKeys.clear()
                } catch (e: CancelledKeyException) {
                    logger.warn("Canceled key, probably shutting session down")
                    break
                } catch (e: ClosedSelectorException) {
                    logger.warn("Selector closed, probably shutting session down")
                    break
                }
            }
        }
    }

    open fun handleReturnTrafficLoop(maxRead: Int): Int {
        val realLimit = min(maxRead, readBuffer.capacity())
        readBuffer.limit(realLimit)
        val len = channel.read(readBuffer)
        if (len > 0) {
            lastHeard = System.currentTimeMillis()
            readBuffer.flip()
            val payload = ByteArray(len)
            readBuffer.get(payload, 0, len)
            logger.debug("Read {} bytes from {}", len, channel)
            handlePayloadFromInternet(payload)
            readBuffer.clear()
        }
        return len
    }

    // should return false if the read failed and we should unsub from reads
    abstract fun read(): Boolean

    fun handleExceptionOnRemoteChannel(e: Exception) {
        logger.error("Error creating session $this : ${e.message}")
        val sourceIpHeader = initialIpHeader
        if (sourceIpHeader == null) {
            logger.error("Initial IP header is null, can't create ICMP packet")
            return
        }
        val code =
            when (sourceIpHeader.sourceAddress) {
                is Inet4Address -> IcmpV4DestinationUnreachableCodes.HOST_UNREACHABLE
                else -> IcmpV6DestinationUnreachableCodes.ADDRESS_UNREACHABLE
            }
        val mtu =
            if (sourceIpHeader.sourceAddress is Inet4Address) {
                TcpOptionMaximumSegmentSize.defaultIpv4MSS
            } else {
                TcpOptionMaximumSegmentSize.defaultIpv6MSS
            }
        val response =
            IcmpFactory.createDestinationUnreachable(
                code,
                // source address for the Icmp header, send it back to the client as if its the clients own OS
                // telling it that its unreachable
                sourceIpHeader.sourceAddress,
                Packet(
                    initialIpHeader,
                    initialTransportHeader,
                    initialPayload,
                ),
                mtu.toInt(),
            )
        returnQueue.add(response)
    }

    /**
     * Should be called after the connection to the remote side is established. This will start the loop that reads
     * from the incoming queue and handles each packet. Until this point, packets will just build up here. This is to
     * prevent us from responding with an ACK before the connection is established.
     */
    fun startIncomingHandling() {
        incomingScope.launch {
            Thread.currentThread().name = "Incoming handler: ${getKey()}"
            while (isRunning.get()) {
                val packet = incomingQueue.take()
                if (packet is SentinelPacket) {
                    logger.debug("Received sentinel packet, stopping session")
                    isRunning.set(false)
                    break
                }
                handlePacketFromClient(packet)
            }
        }
    }

    abstract fun handlePayloadFromInternet(payload: ByteArray)

    abstract fun handlePacketFromClient(packet: Packet)

    open fun getSourceAddress(): InetAddress = initialIpHeader?.sourceAddress ?: throw IllegalArgumentException("No source address")

    open fun getDestinationAddress(): InetAddress =
        initialIpHeader?.destinationAddress ?: throw IllegalArgumentException("No destination address")

    open fun getSourcePort(): UShort = initialTransportHeader?.sourcePort ?: throw IllegalArgumentException("No source port")

    open fun getDestinationPort(): UShort = initialTransportHeader?.destinationPort ?: throw IllegalArgumentException("No destination port")

    open fun getProtocol(): UByte = initialIpHeader?.protocol ?: throw IllegalArgumentException("No protocol")

    /**
     * This should only be called when the selector says we can write to the real channel
     */
    private fun flushToRealChannel(buffer: ByteBuffer) {
        while (buffer.hasRemaining()) {
            channel.write(buffer)
        }
    }

    open fun close(
        removeSession: Boolean = true,
        packet: Packet? = null,
        isIncomingJob: Boolean = false,
    ) {
        logger.debug("Closing session")
        if (channel.isOpen) {
            try {
                channel.close()
            } catch (e: Exception) {
                logger.error("Failed to close channel", e)
            }
        }
        if (selector.isOpen) {
            selector.close()
        }
        if (outgoingToInternet.isOpen) {
            outgoingToInternet.close()
        }
        isRunning.set(false)
        incomingQueue.add(SentinelPacket)
        if (removeSession) {
            // important we remove before the incoming job is cancelled because
            // the handlers sometimes call close and we want' to make sure
            // the session manager cleans up before the thread is cancelled.
            sessionManager.removeSession(this)
        }
        if (packet != null) {
            logger.debug("Re-establishing session")
            // the only time this should be the case is when we're re-establishing a session
            // because we're going from TIME_WAIT to LISTEN because we have an acceptable
            // sequence number

            // important we do this before cancelling the incoming job because otherwise
            // the thread will be cancelled before we handle the packet
            sessionManager.handlePackets(listOf(packet), clientAddress)
        }
        runBlocking {
            logger.debug("Stopping outgoing job")
            outgoingJob.cancelAndJoin()
            logger.debug("Outgoing job stopped. Stopping incoming job")

            if (isIncomingJob) {
                logger.debug("Not cancelling incoming job because we're currently running in it")
            } else {
                incomingJob.cancelAndJoin()
            }

            logger.debug("Incoming job stopped. Stopping channel job")
            channelJob.cancelAndJoin()
            logger.debug("Channel job stopped")
        }
        logger.debug("Session closed")
    }
}
