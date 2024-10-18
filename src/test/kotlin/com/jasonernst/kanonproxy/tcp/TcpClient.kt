package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
import io.mockk.mockk
import org.slf4j.LoggerFactory
import java.io.RandomAccessFile
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
    override val tcpStateMachine = TcpStateMachine(TcpState.CLOSED, mtu, this)

    // this is where the state machine will write into for us to receive it here
    override val channel: ByteChannel = RandomAccessFile("/tmp/buffer.bin", "rw").channel

    private val packetDumper = PcapNgTcpServerPacketDumper()
    private val stringDumper = StringPacketDumper()

    init {
// uncomment for debugging with wireshark
//        packetDumper.start()
//        Thread.sleep(5000) // give some time to connect
    }

    /**
     * Blocks until the three-way handshake completes, or fails
     */
    fun connect() {
        // todo: this assumes a good handshake. update to handle loss, timeout, etc.
        if (tcpStateMachine.tcpState != TcpState.CLOSED) {
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
        packetDumper.dumpBuffer(ByteBuffer.wrap(synPacket.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
        logger.debug("Sending SYN to proxy: ${synPacket.nextHeaders}")
        kAnonProxy.handlePackets(listOf(synPacket))

        logger.debug("Waiting for response from proxy")
        val expectedSynAck = kAnonProxy.takeResponse()
        packetDumper.dumpBuffer(
            ByteBuffer.wrap(expectedSynAck.toByteArray()),
            etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4,
        )
        logger.debug("Got a response, processing")
        val responsePackets =
            tcpStateMachine.processHeaders(
                expectedSynAck.ipHeader,
                expectedSynAck.nextHeaders as TcpHeader,
                expectedSynAck.payload,
            )
        for (packet in responsePackets) {
            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
            logger.debug("Sending to proxy: {}", packet.nextHeaders)
        }
        kAnonProxy.handlePackets(responsePackets)
    }

    /**
     * Blocks until all data is successfully sent
     */
    fun send(buffer: ByteBuffer) {
        if (tcpStateMachine.tcpState != TcpState.ESTABLISHED) {
            throw RuntimeException("Not connected")
        }

        // todo, spin up a thread, track acks until all of the buffer has been acknowledged, then end.
        //   will also need to process recv data in the ACKs into a recv buffer so that when recv is called
        //   we haven't lost anything.

        val packets = tcpStateMachine.encapsulateBuffer(buffer, swapSourceDestination = true)
        for (packet in packets) {
            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
            logger.debug("Sending to proxy: {}", packet)
        }
        kAnonProxy.handlePackets(packets)
    }

    /**
     * Will block until the buffer is full, or the connection is closed
     */
    fun recv(buffer: ByteBuffer) {
        while (buffer.hasRemaining()) {
            val packet = kAnonProxy.takeResponse()
            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
            // assumes everything arrives in order, which it is not guarenteed to do
            if (packet.payload.size > 0) {
                buffer.put(packet.payload)
            }
        }
    }

    /**
     * Finishes any outstanding sends / recvs and then closes the connection cleanly with a FIN
     */
    fun close() {
        // todo: assumes a good shutdown, update to handle loss etc.

        // we probably need to handle some of the other states, see the RFC for when close can be called
        // for now we'll go with the simple case.
        if (tcpStateMachine.tcpState != TcpState.ESTABLISHED) {
            throw RuntimeException("Not in established state, can't close")
        }

        val latestAck =
            if (lastestACKs.isNotEmpty()) {
                (
                    lastestACKs
                        .removeAt(0)
                        .packet.nextHeaders as TcpHeader
                ).acknowledgementNumber
            } else {
                tcpStateMachine.transmissionControlBlock!!.rcv_nxt
            }

        val finPacket =
            TcpHeaderFactory.createFinPacket(
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                seqNumber = tcpStateMachine.transmissionControlBlock!!.snd_nxt,
                ackNumber = latestAck,
                swapSourceAndDestination = false,
                transmissionControlBlock = tcpStateMachine.transmissionControlBlock,
            )
        packetDumper.dumpBuffer(ByteBuffer.wrap(finPacket.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
        kAnonProxy.handlePackets(listOf(finPacket))

        val finAck = kAnonProxy.takeResponse()

        // todo wait for a FIN, send a FIN-ACK - right now there's nothing that triggers the FIN from the proxy side
    }
}
