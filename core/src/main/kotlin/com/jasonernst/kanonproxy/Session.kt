package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.tcp.AnonymousTcpSession
import com.jasonernst.kanonproxy.udp.UdpSession
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.ip.IpHeader
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.transport.TransportHeader
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
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
    protected val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    var lastHeard = System.currentTimeMillis()
    private val outgoingJob = SupervisorJob() // https://stackoverflow.com/a/63407811
    protected val outgoingScope = CoroutineScope(Dispatchers.IO + outgoingJob)

    val incomingQueue = LinkedBlockingDeque<Packet>()
    private val incomingJob = SupervisorJob()
    private val incomingScope = CoroutineScope(Dispatchers.IO + incomingJob)
    private val isRunning = AtomicBoolean(false)

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

    fun getKey(): String = getKey(getSourceAddress(), getSourcePort(), getDestinationAddress(), getDestinationPort(), getProtocol())

    override fun toString(): String =
        "Session(clientAddress='$clientAddress' sourceAddress='${getSourceAddress()}', sourcePort=${getSourcePort()}, destinationAddress='${getDestinationAddress()}', destinationPort=${getDestinationPort()}, protocol=${getProtocol()})"

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

    /**
     * Should be called after the connection to the remote side is established. This will start the loop that reads
     * from the incoming queue and handles each packet. Until this point, packets will just build up here. This is to
     * prevent us from responding with an ACK before the connection is established.
     */
    fun startIncomingHandling() {
        if (isRunning.get()) {
            logger.warn("Incoming handling already started")
            return
        }
        isRunning.set(true)
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

    open fun close(
        removeSession: Boolean = true,
        packet: Packet? = null,
    ) {
        logger.debug("Closing session")
        if (channel.isOpen) {
            try {
                channel.close()
            } catch (e: Exception) {
                logger.error("Failed to close channel", e)
            }
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
            // the only time this should be the case is when we're re-establishing a session
            // because we're going from TIME_WAIT to LISTEN because we have an acceptable
            // sequence number

            // important we do this before cancelling the incoming job because otherwise
            // the thread will be cancelled before we handle the packet
            sessionManager.handlePackets(listOf(packet), clientAddress)
        }
        runBlocking {
            outgoingJob.cancel()
            incomingJob.cancel()
        }
        logger.debug("Session closed")
    }
}
