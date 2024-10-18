package com.jasonernst.kanonproxy.tcp

import com.jasonernst.kanonproxy.KAnonProxy
import com.jasonernst.knet.datalink.EtherType
import com.jasonernst.knet.transport.tcp.InitialSequenceNumberGenerator
import com.jasonernst.knet.transport.tcp.TcpHeader
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import com.jasonernst.packetdumper.stringdumper.StringPacketDumper
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
    ) {
    private val logger = LoggerFactory.getLogger(javaClass)
    override val tcpStateMachine = TcpStateMachine(TcpState.CLOSED, mtu, this)

    // this is where the state machine will write into for us to receive it here
    override val channel: ByteChannel = RandomAccessFile("/tmp/buffer.bin", "rw").channel

    private val packetDumper = PcapNgTcpServerPacketDumper()
    private val stringDumper = StringPacketDumper()

    init {
        packetDumper.start()
        Thread.sleep(5000) // give some time to connect
    }

    /**
     * Blocks until the three-way handshake completes, or fails
     */
    fun connect() {
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
        logger.debug(
            stringDumper.dumpBufferToString(
                ByteBuffer.wrap(synPacket.toByteArray()),
                addresses = true,
                etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4,
            ),
        )
        packetDumper.dumpBuffer(ByteBuffer.wrap(synPacket.toByteArray()), etherType = com.jasonernst.packetdumper.ethernet.EtherType.IPv4)
        logger.debug("Sending SYN to proxy: ${synPacket.nextHeaders}")
        kAnonProxy.handlePackets(listOf(synPacket))

        logger.debug("Waiting for response from proxy")
        val expectedSynAck = kAnonProxy.takeResponse()
        packetDumper.dumpBuffer(ByteBuffer.wrap(expectedSynAck.toByteArray()))
        logger.debug("Got a response, processing")
        val responsePackets =
            tcpStateMachine.processHeaders(
                expectedSynAck.ipHeader,
                expectedSynAck.nextHeaders as TcpHeader,
                expectedSynAck.payload,
            )
        for (packet in responsePackets) {
            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()))
            logger.debug("Sending ${packet.nextHeaders} to proxy")
        }
        kAnonProxy.handlePackets(responsePackets)
    }

    /**
     * Blocks until all data is successfully sent
     */
    fun send(buffer: ByteBuffer) {
    }

    /**
     * Will block until the buffer is full, or the connection is closed
     */
    fun recv(buffer: ByteBuffer) {
    }

    /**
     * Finishes any outstanding sends / recvs and then closes the connection cleanly with a FIN
     */
    fun close() {
    }
}
