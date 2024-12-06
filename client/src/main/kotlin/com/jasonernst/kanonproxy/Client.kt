package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import com.jasonernst.knet.Packet.Companion.parseStream
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.packetdumper.AbstractPacketDumper
import com.jasonernst.packetdumper.DummyPacketDumper
import com.jasonernst.packetdumper.ethernet.EtherType
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/**
 * Abstract client that can support Linux, Android, etc implementations that are specific to their
 * tun/tap device.
 */
abstract class Client(
    private val socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080),
    private val packetDumper: AbstractPacketDumper = DummyPacketDumper,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val socket = DatagramSocket()

    private val isConnected = AtomicBoolean(false)
    private lateinit var readFromTunJob: CompletableJob
    private lateinit var readFromTunJobScope: CoroutineScope
    private lateinit var readFromProxyJob: CompletableJob
    private lateinit var readFromProxyJobScope: CoroutineScope

    companion object {
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)
    }

    fun connect() {
        if (isConnected.get()) {
            logger.debug("Client is already connected")
            return
        }

        readFromProxyJob = SupervisorJob()
        readFromProxyJobScope = CoroutineScope(Dispatchers.IO + readFromProxyJob)
        readFromProxyJobScope.launch {
            logger.debug("Connecting to server: {}", socketAddress)
            try {
                socket.connect(socketAddress)
                logger.debug("Connected to server: {}", socketAddress)
                isConnected.set(true)

                readFromTunJob = SupervisorJob()
                readFromTunJobScope = CoroutineScope(Dispatchers.IO + readFromTunJob)
                readFromTunJobScope.launch {
                    readFromTunWriteToProxy()
                }

                readFromProxyWriteToTun()
            } catch (e: Exception) {
                logger.error("Failed to connect to server")
            }
        }
    }

    fun waitUntilShutdown() {
        // block until the read jobs are finished
        runBlocking {
            if (readFromProxyJob.complete().not()) {
                readFromProxyJob.join()
            }
            if (readFromTunJob.complete().not()) {
                readFromTunJob.join()
            }
        }
    }

    abstract fun tunRead(
        readBytes: ByteArray,
        bytesToRead: Int,
    ): Int

    abstract fun tunWrite(writeBytes: ByteArray)

    private fun readFromProxyWriteToTun() {
        val buffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val datagram = DatagramPacket(buffer, buffer.size)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isConnected.get()) {
            // logger.debug("Waiting for response from server")
            try {
                socket.receive(datagram)
            } catch (e: Exception) {
                logger.error("Error receiving from server: $e")
                break
            }
            stream.put(buffer, 0, datagram.length)
            stream.flip()
            val packets = parseStream(stream)
            for (packet in packets) {
                if (packet is SentinelPacket) {
                    logger.debug("Sentinel packet, skip")
                    continue
                }
                logger.debug("From proxy: $packet")
                tunWrite(packet.toByteArray())
                packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = EtherType.DETECT)
            }
        }
        logger.warn("No longer reading from server")
    }

    private fun writePackets(packets: List<Packet>) {
        packets.forEach { packet ->
            val buffer = packet.toByteArray()
            val datagramPacket = DatagramPacket(buffer, buffer.size, socketAddress)
            socket.send(datagramPacket)
            packetDumper.dumpBuffer(ByteBuffer.wrap(buffer), etherType = EtherType.DETECT)
        }
    }

    private fun readFromTunWriteToProxy() {
        val readBuffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isConnected.get()) {
            val bytesToRead = min(MAX_RECEIVE_BUFFER_SIZE, stream.remaining())
            val bytesRead =
                try {
                    tunRead(readBuffer, bytesToRead)
                } catch (e: Exception) {
                    logger.warn("Exception trying to read from proxy, probably shutting down")
                    break
                }
            if (bytesRead == -1) {
                logger.warn("End of OS stream")
                break
            }
            if (bytesRead > 0) {
                stream.put(readBuffer, 0, bytesRead)
                // logger.debug("Read {} bytes from OS. position: {} remaining {}", bytesRead, stream.position(), stream.remaining())
                stream.flip()
                // logger.debug("After flip: position: {} remaining {}", stream.position(), stream.remaining())
                val packets = parseStream(stream)
                for (packet in packets) {
                    logger.debug("To proxy: $packet")
                }
                // logger.debug("After parse: position: {} remaining {}", stream.position(), stream.remaining())
                writePackets(packets)
            }
        }
        logger.warn("No longer reading from TUN adapter")
    }

    fun close() {
        logger.debug("Stopping client")
        isConnected.set(false)
        socket.close()
        runBlocking {
            logger.debug("Waiting for tun reader to stop")
            if (readFromTunJob.complete().not()) {
                readFromTunJob.join()
            }
            logger.debug("Stopped, waiting for proxy reader to stop")
            if (readFromProxyJob.complete().not()) {
                readFromProxyJob.join()
            }
            logger.debug("Stopped")
        }
        logger.debug("Client stopped")
    }
}
