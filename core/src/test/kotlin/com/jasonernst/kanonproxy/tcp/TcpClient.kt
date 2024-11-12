package com.jasonernst.kanonproxy.tcp

import com.jasonernst.icmp.common.v4.IcmpV4DestinationUnreachablePacket
import com.jasonernst.icmp.common.v6.IcmpV6DestinationUnreachablePacket
import com.jasonernst.kanonproxy.BidirectionalByteChannel
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.kanonproxy.tcp.TcpStateMachine.Companion.G
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.network.ip.IpType
import com.jasonernst.knet.network.nextheader.IcmpNextHeaderWrapper
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.knet.transport.tcp.options.TcpOptionMaximumSegmentSize
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketException
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.util.UUID
import java.util.concurrent.LinkedBlockingDeque

/**
 * A "TCP client" that has its own state machine, processes packets, and generates new packets to send.
 *
 * Can also send a data stream and receive one.
 */
class TcpClient(
    private val sourceAddress: InetAddress,
    private val destinationAddress: InetAddress,
    private val sourcePort: UShort,
    private val destinationPort: UShort,
    val kAnonProxy: KAnonProxy,
    val packetDumper: AbstractPacketDumper = DummyPacketDumper,
) : TcpSession(
        null,
        null,
        null,
        returnQueue = LinkedBlockingDeque(),
        mockk(relaxed = true),
    ) {
    private val clientId = UUID.randomUUID()
    private val logger = LoggerFactory.getLogger(javaClass)
    private val clientAddress = InetSocketAddress(InetAddress.getByName("127.0.0.1"), 1234)

    override val mtu: UShort =
        if (sourceAddress is Inet4Address) {
            TcpOptionMaximumSegmentSize.defaultIpv4MSS
        } else {
            TcpOptionMaximumSegmentSize.defaultIpv6MSS
        }

    override val tcpStateMachine = TcpStateMachine(MutableStateFlow(TcpState.CLOSED), mtu, this, swapSourceDestination = true)

    // this is where the state machine will write into for us to receive it here
    override val channel: ByteChannel = BidirectionalByteChannel()
    private val stringDumper = StringPacketDumper()

    private val outgoingPackets = LinkedBlockingDeque<Packet>()

    private var isRunning = false
    private val readJob: Job
    private val writeJob: Job
    private val maintenanceJob = SupervisorJob() // https://stackoverflow.com/a/63407811
    private val maintenanceScope = CoroutineScope(Dispatchers.IO + maintenanceJob)

    init {
        isRunning = true

        readJob =
            CoroutineScope(Dispatchers.IO).launch {
                Thread.currentThread().name = "TcpClient writer $clientId"
                writerThread()
            }

        writeJob =
            CoroutineScope(Dispatchers.IO).launch {
                Thread.currentThread().name = "TcpClient reader $clientId"
                readerThread()
            }

        maintenanceScope.launch {
            sessionMaintenanceThread()
        }
    }

    fun writerThread() {
        while (isRunning) {
            val packet = outgoingPackets.take()
            if (packet == SentinelPacket) {
                logger.warn("Got sentinel packet, stopping writer")
                break
            }
            logger.debug("Sending to proxy in state: {}: {}", tcpStateMachine.tcpState.value, packet)
            packetDumper.dumpBuffer(
                ByteBuffer.wrap(packet.toByteArray()),
                etherType = EtherType.DETECT,
            )
            kAnonProxy.handlePackets(listOf(packet), clientAddress)
        }
    }

    fun readerThread() {
        while (isRunning) {
            val packet = kAnonProxy.takeResponse(clientAddress)
            if (packet == SentinelPacket) {
                logger.warn("Got sentinel packet, stopping reader")
                break
            }
            if (packet.ipHeader == null || packet.nextHeaders == null || packet.payload == null) {
                logger.debug("missing header(s) or payload, skipping packet")
                continue
            }
            logger.debug("Received from proxy in state: {}: {}", tcpStateMachine.tcpState.value, packet.nextHeaders)
            packetDumper.dumpBuffer(
                ByteBuffer.wrap(packet.toByteArray()),
                etherType = EtherType.DETECT,
            )

            if (packet.nextHeaders is TcpHeader) {
                val responses =
                    tcpStateMachine.processHeaders(
                        packet.ipHeader!!,
                        packet.nextHeaders as TcpHeader,
                        packet.payload!!,
                    )
                for (response in responses) {
                    outgoingPackets.add(response)
                }
            } else if (packet.nextHeaders is IcmpNextHeaderWrapper) {
                val icmpHeader = (packet.nextHeaders as IcmpNextHeaderWrapper).icmpHeader
                if (icmpHeader is IcmpV4DestinationUnreachablePacket || icmpHeader is IcmpV6DestinationUnreachablePacket) {
                    logger.debug("Got Icmp unreachable, closing")
                    closeClient()
                }
            }
        }
    }

    private suspend fun sessionMaintenanceThread() {
        logger.debug("Session maintenance thread is started")
        while (isRunning) {
            val startTime = System.currentTimeMillis()
            val reverseAcks = tcpStateMachine.checkForReverseAcks(this)
            for (reverseAck in reverseAcks) {
                logger.warn(
                    "Waited over 500 ms for reverse traffic, enqueuing ACK " +
                        "${(reverseAck.nextHeaders as TcpHeader).acknowledgementNumber}",
                )
                outgoingPackets.add(reverseAck)
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
        logger.warn("Session maintenance thread is (stop)ped")
    }

    /**
     * Blocks until the three-way handshake completes, or fails
     */
    fun connect(timeOutMs: Long = 2000) {
        if (tcpStateMachine.tcpState.value != TcpState.CLOSED) {
            throw RuntimeException("Can't connect, current session isn't closed")
        }
        tcpStateMachine.activeOpen()

        val iss =
            InitialSequenceNumberGenerator.generateInitialSequenceNumber(
                sourceAddress.hostAddress,
                sourcePort.toInt(),
                destinationAddress.hostAddress,
                destinationPort.toInt(),
            )
        val synPacket =
            TcpHeaderFactory.createSynPacket(
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                iss,
                mtu,
                tcpStateMachine.transmissionControlBlock!!,
            )
        initialIpHeader = synPacket.ipHeader
        initialTransportHeader = synPacket.nextHeaders as TcpHeader
        initialPayload = synPacket.payload
        logger.debug("$clientId Sending SYN to proxy: ${synPacket.nextHeaders}")
        outgoingPackets.add(synPacket)

        // this will block until we reach the established state or closed state, or until a timeout occurs
        // if a timeout occurs, an exception will be thrown
        runBlocking {
            withTimeout(timeOutMs) {
                tcpStateMachine.tcpState
                    .takeWhile {
                        it != TcpState.ESTABLISHED && it != TcpState.CLOSED
                    }.collect {
                        logger.debug("$clientId State: $it")
                    }
            }
        }
        if (tcpStateMachine.tcpState.value != TcpState.ESTABLISHED) {
            throw SocketException("$clientId Failed to connect")
        }
    }

    /**
     * Blocks until all data is successfully sent (and ACK'd)
     */
    fun send(buffer: ByteBuffer) {
        if (tcpStateMachine.tcpState.value != TcpState.ESTABLISHED) {
            throw RuntimeException("Not connected")
        }

        val startingSequenceNumber = tcpStateMachine.transmissionControlBlock!!.snd_nxt
        val finSequenceNumber = startingSequenceNumber + buffer.remaining().toUInt()

        while (buffer.hasRemaining()) {
            tcpStateMachine.enqueueOutgoingData(buffer)
            val packets = tcpStateMachine.encapsulateOutgoingData(true)
            outgoingPackets.addAll(packets)
        }

        runBlocking {
            tcpStateMachine.transmissionControlBlock!!
                .snd_una
                .takeWhile {
                    it < finSequenceNumber
                }.collect {
                    logger.debug("ACK'd: $it, waiting for $finSequenceNumber")
                }
        }
    }

    /**
     * Will block until the buffer is full, a PSH is received, or the connection is closed
     */
    fun recv(buffer: ByteBuffer) {
        logger.debug("Waiting for up to ${buffer.remaining()} bytes")
        while (buffer.hasRemaining()) {
            val byteRead = channel.read(buffer)
            logger.debug("READ: $byteRead")
            if (isPsh.get()) {
                isPsh.set(false)
                logger.debug("PSH received, returning from read before buffer full")
                break
            }
            if (tearDownPending.get()) {
                logger.debug("TEARDOWN pending, returning from read before buffer full")
                break
            }
//            val packet = kAnonProxy.takeResponse()
//            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
//            // assumes everything arrives in order, which it is not guarenteed to do
//            if (packet.payload.size > 0) {
//                buffer.put(packet.payload)
//            }
        }
        logger.debug("Finished reading")
    }

    /**
     * Finishes any outstanding sends / recvs and then closes the connection cleanly with a FIN
     */
    fun closeClient(waitForTimeWait: Boolean = false) {
        // send the FIN
        val finPacket = super.teardown(false)
        if (finPacket != null) {
            logger.debug("Sending FIN to proxy: ${finPacket.nextHeaders}")
            outgoingPackets.add(finPacket)
        }

        // this will block until we reach the established state or closed state, or until a timeout occurs
        // if a timeout occurs, an exception will be thrown
        runBlocking {
            val timeout =
                if (waitForTimeWait) {
                    // it's supposed to take 2MSL to close, so we'll wait for that plus a bit of wiggle room
                    ((2 * TcpStateMachine.MSL * 1000) + 1000).toLong()
                } else {
                    1000.toLong()
                }
            withTimeout(timeout) {
                val flow =
                    if (waitForTimeWait) {
                        tcpStateMachine.tcpState.takeWhile { it != TcpState.CLOSED }
                    } else {
                        // if we aren't waiting for the TIME_WAIT timer, we can consider it closed on TIME_WAIT
                        tcpStateMachine.tcpState.takeWhile { it != TcpState.CLOSED && it != TcpState.TIME_WAIT }
                    }

                flow.collect {
                    logger.debug("State: $it")
                }
            }
        }
        // give a little extra time for the ACK for the FIN to from the other side to be enqueued and sent out
        Thread.sleep(100)
        runBlocking {
            isRunning = false
            outgoingPackets.add(SentinelPacket)
            logger.debug("Waiting for readjob to finish")
            readJob.join()
            if (!waitForTimeWait) {
                kAnonProxy.disconnectSession()
            }
            logger.debug("Waiting for writejob to finish")
            writeJob.join()
            logger.debug("Jobs finished")
        }
        if (waitForTimeWait) {
            if (tcpStateMachine.tcpState.value != TcpState.CLOSED) {
                throw RuntimeException("Failed to close, state: ${tcpStateMachine.tcpState.value}")
            }
        } else {
            if (tcpStateMachine.tcpState.value != TcpState.TIME_WAIT && tcpStateMachine.tcpState.value != TcpState.CLOSED) {
                throw RuntimeException("Failed to close, state: ${tcpStateMachine.tcpState.value}")
            }
        }
    }

    override fun toString(): String =
        "TcpClient(sourceAddress='$sourceAddress', destinationAddress='$destinationAddress', sourcePort=$sourcePort, destinationPort=$destinationPort, clientId=$clientId)"

    /**
     * In the Tcp Client, this is actually handling packets it got from the proxy
     */
    override fun handlePacketFromClient(packet: Packet) {
        logger.error("GOT HERE")
    }

    override fun getSourcePort(): UShort = sourcePort

    override fun getDestinationPort(): UShort = destinationPort

    override fun getSourceAddress(): InetAddress = sourceAddress

    override fun getDestinationAddress(): InetAddress = destinationAddress

    override fun getProtocol(): UByte = IpType.TCP.value
}
