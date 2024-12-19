package com.jasonernst.kanonproxy

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachableCodes
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachableCodes
import com.jasonernst.kanonproxy.KAnonProxy.Companion.STALE_SESSION_MS
import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession
import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession.Companion.CONNECTION_POLL_MS
import com.jasonernst.kanonproxy.tcp.TcpSession
import com.jasonernst.kanonproxy.udp.UdpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.icmp.IcmpFactory
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.TransportHeader
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
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
import java.nio.channels.SelectionKey.OP_CONNECT
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
    val trafficAccounting: TrafficAccounting = DummyTrafficAccount,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    abstract val channel: ByteChannel
    protected val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    var lastHeard = System.currentTimeMillis()
    protected lateinit var outgoingJob: CompletableJob // https://stackoverflow.com/a/63407811
    protected lateinit var outgoingScope: CoroutineScope

    val incomingQueue = LinkedBlockingDeque<Packet>()
    val outgoingQueue = LinkedBlockingDeque<ByteBuffer>()
    private lateinit var incomingJob: CompletableJob
    private lateinit var incomingScope: CoroutineScope
    protected val isRunning = AtomicBoolean(true)

    private lateinit var selectorJob: CompletableJob
    private lateinit var selectorScope: CoroutineScope

    val isConnecting = AtomicBoolean(true)
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
        fun getNewSession(
            initialIPHeader: IpHeader,
            initialTransportHeader: TransportHeader,
            initialPayload: ByteArray,
            returnQueue: LinkedBlockingDeque<Packet>,
            protector: VpnProtector,
            sessionManager: SessionManager,
            clientAddress: InetSocketAddress,
            trafficAccounting: TrafficAccounting,
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
                        trafficAccounting,
                    )
                }
                IpType.TCP.value -> {
                    val tcpHeader = initialTransportHeader as TcpHeader
                    if (tcpHeader.isSyn().not()) {
                        throw IllegalArgumentException("Can't start TcpSession without a SYN packet")
                    }
                    AnonymousTcpSession(
                        initialIPHeader,
                        initialTransportHeader,
                        initialPayload,
                        returnQueue,
                        protector,
                        sessionManager,
                        clientAddress,
                        trafficAccounting,
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
        if (isConnecting.get()) {
            logger.debug("Still connecting, don't switch to write mode yet")
        }
        if (channel is BidirectionalByteChannel) {
            return
        }
        if (isConnecting.get().not()) {
            logger.debug("Adding CHANGE request to write")
            synchronized(changeRequests) {
                changeRequests.add(ChangeRequest(channel as AbstractSelectableChannel, ChangeRequest.CHANGE_OPS, SelectionKey.OP_WRITE))
            }
            selector.wakeup()
        }
    }

    fun startSelector() {
        outgoingJob = SupervisorJob()
        outgoingScope = CoroutineScope(Dispatchers.IO + outgoingJob)
        incomingJob = SupervisorJob()
        incomingScope = CoroutineScope(Dispatchers.IO + incomingJob)
        selectorJob = SupervisorJob()
        selectorScope = CoroutineScope(Dispatchers.IO + selectorJob)
        val session = this
        selectorScope.launch {
            if (isRunning.get().not()) {
                logger.debug("Session shutting down before starting")
                return@launch
            }
            val oldThreadName = Thread.currentThread().name
            Thread.currentThread().name = "Selector: ${getKey()}"

            if (session is AnonymousTcpSession) {
                (channel as SocketChannel).register(selector, OP_CONNECT)
            }

            while (isRunning.get()) {
                if (sessionManager.isRunning().not()) {
                    logger.warn("Session manager is no longer running, shutting down")
                    break
                }
                try {
                    // Process any pending changes
                    synchronized(changeRequests) {
                        for (changeRequest in changeRequests) {
                            when (changeRequest.type) {
                                ChangeRequest.REGISTER -> {
                                    logger.debug("Processing REGISTER: ${changeRequest.ops}")
                                    changeRequest.channel.register(selector, changeRequest.ops)
                                }
                                ChangeRequest.CHANGE_OPS -> {
                                    logger.debug("Processing CHANGE_OPS: ${changeRequest.ops}")
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
                        if (session is AnonymousTcpSession && session.isConnecting.get() && session.connectTime != 0L) {
                            val currentTime = System.currentTimeMillis()
                            val difference = currentTime - session.connectTime
                            if (difference > STALE_SESSION_MS) {
                                val error =
                                    "Timed out trying to reach remote on TCP connect. " +
                                        "Connect time: ${session.connectTime}, currentTime: " +
                                        "$currentTime, difference: $difference"
                                logger.error(error)
                                // selector.keys().clear()
                                // session.reconnectRemoteChannel()

                                handleExceptionOnRemoteChannel(Exception(error))
                                selector.close()
                                break
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
                        // logger.warn("SELECT: ${selectedKeys.toString()}")
                    }
                    val keyStream = selectedKeys.parallelStream()
                    keyStream
                        .forEach {
                            if (!it.isValid) {
                                logger.error("INVALID KEY!!! ${keyToString(it)}")
                            }
                            if (it.isWritable && it.isValid) {
                                logger.debug("WRITABLE KEY: ${keyToString(it)}")
                                // could do a while loop here, but others might starve
                                if (outgoingQueue.isNotEmpty()) {
                                    val queue = outgoingQueue.take()
                                    logger.debug("Writing ${queue.limit()} bytes to remote channel")
                                    while (queue.hasRemaining()) {
                                        val bytesWritten = channel.write(queue)
                                        trafficAccounting.recordToInternet(bytesWritten.toLong())
                                    }
                                }
                                if (outgoingQueue.isNotEmpty()) {
                                    logger.debug("Outgoing queue not empty, continuing interest in writes")
                                    it.interestOps(SelectionKey.OP_WRITE)
                                } else {
                                    logger.debug("Queue empty, returning to read mode")
                                    it.interestOps(SelectionKey.OP_READ)
                                }
                            }
                            if (it.isReadable && it.isValid) {
                                logger.debug("READABLE KEY: ${keyToString(it)}")
                                if (!read()) {
                                    logger.warn("Remote read failed, closing selector")
                                    it.interestOps(0)
                                    selector.close()
                                }
                            }
                            if (it.isConnectable && it.isValid) {
                                // AFAIK its only possible to be here if its a SocketChannel
                                val socketChannel = it.channel() as SocketChannel
                                if (socketChannel.isConnectionPending) {
                                    logger.debug("CONNECTING PENDING KEY: ${keyToString(it)}")
                                    try {
                                        val result = socketChannel.finishConnect()
                                        if (result) {
                                            logger.debug("Tcp connection successful")
                                            isConnecting.set(false)
                                            startIncomingHandling()
                                            if (outgoingQueue.isNotEmpty()) {
                                                it.interestOps(SelectionKey.OP_WRITE)
                                            } else {
                                                it.interestOps(SelectionKey.OP_READ)
                                            }
                                        } else {
                                            logger.debug("Finishing connection, still in progress")
                                            // will retry again when the selector wakes up
                                        }
                                    } catch (e: Exception) {
                                        logger.error("Failed to finish connecting: $e")
                                        handleExceptionOnRemoteChannel(e)
                                        selector.close()
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
                } catch (e: Exception) {
                    logger.warn("Exception trying write to remote channel, probably shutting down")
                    break
                }
            }
            logger.warn("selector job complete")
            Thread.currentThread().name = oldThreadName
            selectorJob.complete()
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
            trafficAccounting.recordToInternet(len.toLong())
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
        try {
            selector.close()
        } catch (e: Exception) {
            logger.warn("Error closing selector")
        }
    }

    /**
     * Should be called after the connection to the remote side is established. This will start the loop that reads
     * from the incoming queue and handles each packet. Until this point, packets will just build up here. This is to
     * prevent us from responding with an ACK before the connection is established.
     */
    fun startIncomingHandling() {
        incomingScope.launch {
            val oldThreadName = Thread.currentThread().name
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
            logger.debug("Incoming handler complete")
            Thread.currentThread().name = oldThreadName
            incomingJob.complete()
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

    open fun close(
        removeSession: Boolean = true,
        packet: Packet? = null,
        isIncomingJob: Boolean = false,
    ) {
        logger.debug("Closing session")
        isRunning.set(false)
        try {
            logger.debug("Closing selector")
            selector.close()
            logger.debug("Selector closed")
        } catch (e: Exception) {
            logger.error("Failed to close selector", e)
        }
        if (this is AnonymousTcpSession) {
            try {
                logger.debug("Closing remote tcp channel")
                channel.socket().close()
                logger.debug("Remote tcp channel closed")
            } catch (e: Exception) {
                logger.error("Error closing socket", e)
            }
        } else {
            try {
                logger.debug("Closing remote UDP channel")
                channel.close()
                logger.debug("Remote UDP channel closed")
            } catch (e: Exception) {
                logger.error("Failed to close channel", e)
            }
        }
        logger.debug("Stopping incoming queue thread with sentinel packet")
        incomingQueue.add(SentinelPacket)
        if (removeSession) {
            logger.debug("Removing this session from session manager")
            // important we remove before the incoming job is cancelled because
            // the handlers sometimes call close and we want' to make sure
            // the session manager cleans up before the thread is cancelled.
            sessionManager.removeSession(this)
            logger.debug("Session removed")
        }
        runBlocking {
            logger.debug("Stopping outgoing job")
            outgoingJob.cancelAndJoin()
            logger.debug("Outgoing job stopped")

            if (isIncomingJob) {
                logger.debug("Not cancelling incoming job because we're currently running in it")
            } else {
                logger.debug("Stopping incoming job")
                incomingJob.cancelAndJoin()
                logger.debug("Incoming job stopped")
            }

            logger.debug("Incoming job stopped. Stopping channel job")
            selectorJob.cancelAndJoin()
            logger.debug("Channel job stopped")
        }

        if (this is TcpSession) {
            this.tcpStateMachine.stopJobs()
        }

        outgoingScope.cancel()
        incomingScope.cancel()
        selectorScope.cancel()
        logger.debug("Session closed")

        // this must only be done after the session has properly stopped its jobs
        if (packet != null) {
            logger.debug("Re-establishing session")
            // the only time this should be the case is when we're re-establishing a session
            // because we're going from TIME_WAIT to LISTEN because we have an acceptable
            // sequence number

            // important we do this before cancelling the incoming job because otherwise
            // the thread will be cancelled before we handle the packet
            sessionManager.handlePackets(listOf(packet), clientAddress)
        }
    }

    fun testCloseChannel() {
        try {
            channel.close()
        } catch (e: Exception) {
            logger.warn("Failed to close channel")
        }
    }

    /**
     * Helper function to print useful info from a selector
     */
    fun keyToString(selectionKey: SelectionKey): String {
        val sb = StringBuilder()
        sb
            .append("channel=")
            .append(selectionKey.channel())
            .append(", selector=")
            .append(selector)
        if (selectionKey.isValid) {
            sb
                .append(", interestOps=")
                .append(selectionKey.interestOps())
                .append(", readyOps=")
                .append(selectionKey.readyOps())
        } else {
            sb.append(", invalid")
        }

        return sb.toString()
    }
}
