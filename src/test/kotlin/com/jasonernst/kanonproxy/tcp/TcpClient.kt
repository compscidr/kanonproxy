package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.BidirectionalByteChannel
import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.Packet
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import io.mockk.mockk
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.slf4j.LoggerFactory
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.util.concurrent.LinkedBlockingDeque

/**
 * A "TCP client" that has its own state machine, processes packets, and generates new packets to send.
 *
 * Can also send a data stream and receive one.
 */
class TcpClient(
    sourceAddress: InetAddress,
    destinationAddress: InetAddress,
    sourcePort: UShort,
    destinationPort: UShort,
    val kAnonProxy: KAnonProxy,
) : TcpSession(
        sourceAddress = sourceAddress,
        sourcePort = sourcePort,
        destinationAddress = destinationAddress,
        destinationPort = destinationPort,
        returnQueue = LinkedBlockingDeque(),
        mockk(relaxed = true),
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine = TcpStateMachine(MutableStateFlow(TcpState.CLOSED), mtu, this)

    // this is where the state machine will write into for us to receive it here
    override val channel: ByteChannel = BidirectionalByteChannel()

    private val packetDumper = PcapNgTcpServerPacketDumper(isSimple = false)
    private val stringDumper = StringPacketDumper()

    private val outgoingPackets = LinkedBlockingDeque<Packet>()

    private var isRunning = false
    private val readJob: Job
    private val writeJob: Job

    init {
        // uncomment for debugging with wireshark
        packetDumper.start()
        Thread.sleep(5000) // give some time to connect

        isRunning = true

        readJob =
            CoroutineScope(Dispatchers.IO).launch {
                Thread.currentThread().name = "TcpClient writer"
                writerThread()
            }

        writeJob =
            CoroutineScope(Dispatchers.IO).launch {
                Thread.currentThread().name = "TcpClient reader"
                readerThread()
            }
    }

    fun writerThread() {
        while (isRunning) {
            val packet = outgoingPackets.take()
            if (packet == SentinelPacket) {
                logger.debug("Got sentinel packet, stopping")
                break
            }
            logger.debug("Sending to proxy: {}", packet)
            packetDumper.dumpBuffer(
                ByteBuffer.wrap(packet.toByteArray()),
                etherType = com.jasonernst.packetdumper.ethernet.EtherType.DETECT,
            )
            kAnonProxy.handlePackets(listOf(packet))
        }
    }

    fun readerThread() {
        while (isRunning) {
            val packet = kAnonProxy.takeResponse()
            if (packet == SentinelPacket) {
                logger.debug("Got sentinel packet, stopping")
                break
            }
            if (packet.ipHeader == null || packet.nextHeaders == null || packet.payload == null) {
                logger.debug("missing header(s) or payload, skipping packet")
                continue
            }
            logger.debug("Received from proxy: {}", packet)
            packetDumper.dumpBuffer(
                ByteBuffer.wrap(packet.toByteArray()),
                etherType = com.jasonernst.packetdumper.ethernet.EtherType.DETECT,
            )
            val responses =
                tcpStateMachine.processHeaders(
                    packet.ipHeader!!,
                    packet.nextHeaders as TcpHeader,
                    packet.payload!!,
                )
            for (response in responses) {
                outgoingPackets.add(response)
            }
        }
    }

    /**
     * Blocks until the three-way handshake completes, or fails
     */
    fun connect() {
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
        logger.debug("Sending SYN to proxy: ${synPacket.nextHeaders}")
        outgoingPackets.add(synPacket)

        // this will block until we reach the established state or closed state, or until a timeout occurs
        // if a timeout occurs, an exception will be thrown
        runBlocking {
            withTimeout(1000) {
                tcpStateMachine.tcpState
                    .takeWhile {
                        it != TcpState.ESTABLISHED && it != TcpState.CLOSED
                    }.collect {
                        logger.debug("State: $it")
                    }
            }
        }
        if (tcpStateMachine.tcpState.value != TcpState.ESTABLISHED) {
            throw RuntimeException("Failed to connect")
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

        // todo: convert this to a flow so we don't need to stupid sleep
        while (tcpStateMachine.transmissionControlBlock!!.snd_una < finSequenceNumber) {
            logger.debug("waiting for sent data to be ack'd")
            Thread.sleep(100)
        }

//
//        val packets = tcpStateMachine.encapsulateBuffer(buffer, swapSourceDestination = true)
//        for (packet in packets) {
//            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
//            logger.debug("Sending to proxy: {}", packet)
//        }
//        kAnonProxy.handlePackets(packets)
    }

    /**
     * Will block until the buffer is full, a PSH is received, or the connection is closed
     */
    fun recv(buffer: ByteBuffer) {
        while (buffer.hasRemaining()) {
            val byteRead = channel.read(buffer)
            logger.debug("READ: $byteRead")
//            val packet = kAnonProxy.takeResponse()
//            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
//            // assumes everything arrives in order, which it is not guarenteed to do
//            if (packet.payload.size > 0) {
//                buffer.put(packet.payload)
//            }
        }
    }

    /**
     * Finishes any outstanding sends / recvs and then closes the connection cleanly with a FIN
     */
    fun closeClient(waitForTimeWait: Boolean = false) {
        // we probably need to handle some of the other states, see the RFC for when close can be called
        // for now we'll go with the simple case.
        if (tcpStateMachine.tcpState.value != TcpState.ESTABLISHED) {
            throw RuntimeException("Not in established state, can't close")
        }

        // send the FIN
        val finPacket = super.close(false)
        if (finPacket != null) {
            logger.debug("Sending FIN to proxy: ${finPacket.nextHeaders}")
            outgoingPackets.add(finPacket)
        } else {
            throw RuntimeException("Failed to close, no FIN packet generated")
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
        runBlocking {
            isRunning = false
            outgoingPackets.add(SentinelPacket)
            logger.debug("Waiting for readjob to finish")
            readJob.cancelAndJoin()
            logger.debug("Waiting for writejob to finish")
            writeJob.cancelAndJoin()
            logger.debug("Jobs finished")
        }
        packetDumper.stop()
        if (waitForTimeWait) {
            if (tcpStateMachine.tcpState.value != TcpState.CLOSED) {
                throw RuntimeException("Failed to close")
            }
        } else {
            if (tcpStateMachine.tcpState.value != TcpState.TIME_WAIT) {
                throw RuntimeException("Failed to close")
            }
        }
    }
}
