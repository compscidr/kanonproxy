package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.ChangeRequest.Companion.CHANGE_OPS
import com.jasonernst.kanonproxy.ChangeRequest.Companion.REGISTER
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
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey.OP_READ
import java.nio.channels.SelectionKey.OP_WRITE
import java.nio.channels.Selector
import java.util.LinkedList
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/**
 * Abstract client that can support Linux, Android, etc implementations that are specific to their
 * tun/tap device.
 *
 * @param datagramChannel - A datagram channel which has already been set into non-blocking mode
 *   and connected to the server (ie, just have the server destination addressed associated with
 *   the channel since UDP sockets can't "connect").
 */
abstract class Client(
    private val datagramChannel: DatagramChannel,
    private val packetDumper: AbstractPacketDumper = DummyPacketDumper,
    private val onlyDestinations: List<InetAddress> = emptyList(),
    private val onlyProtocols: List<UByte> = emptyList(),
) {
    private val logger = LoggerFactory.getLogger(javaClass)

    private lateinit var selector: Selector
    private lateinit var selectorJob: CompletableJob
    private lateinit var selectorScope: CoroutineScope
    private val outgoingQueue = LinkedBlockingDeque<ByteBuffer>() // queue of data for the server
    private val changeRequests = LinkedList<ChangeRequest>()
    private val fromProxyStream: ByteBuffer = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

    private val isRunning = AtomicBoolean(false)
    private lateinit var readFromTunJob: CompletableJob
    private lateinit var readFromTunJobScope: CoroutineScope

    companion object {
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)
    }

    fun start() {
        if (isRunning.get()) {
            logger.warn("Already running")
            return
        }
        isRunning.set(true)
        selector = Selector.open()

        selectorJob = SupervisorJob()
        selectorScope = CoroutineScope(Dispatchers.IO + selectorJob)
        selectorScope.launch {
            selectorLoop()
        }

        readFromTunJob = SupervisorJob()
        readFromTunJobScope = CoroutineScope(Dispatchers.IO + readFromTunJob)
        readFromTunJobScope.launch {
            readFromTunWriteToProxy()
        }
    }

    fun waitUntilShutdown() {
        // block until the read jobs are finished
        runBlocking {
            selectorJob.join()
            readFromTunJob.join()
        }
    }

    abstract fun tunRead(
        readBytes: ByteArray,
        bytesToRead: Int,
    ): Int

    abstract fun tunWrite(writeBytes: ByteArray)

    private fun selectorLoop() {
        datagramChannel.register(selector, OP_READ)

        while (isRunning.get()) {
            synchronized(changeRequests) {
                for (changeRequest in changeRequests) {
                    when (changeRequest.type) {
                        REGISTER -> {
                            // logger.debug("Processing REGISTER: ${changeRequest.ops}")
                            changeRequest.channel.register(selector, changeRequest.ops)
                        }
                        CHANGE_OPS -> {
                            // logger.debug("Processing CHANGE_OPS: ${changeRequest.ops}")
                            val key = changeRequest.channel.keyFor(selector)
                            key.interestOps(changeRequest.ops)
                        }
                    }
                }
                changeRequests.clear()
            }

            try {
                val numKeys = selector.select()
                // we won't get any keys if we wakeup the selector before we select
                // (ie, when we make changes to the keys or interest-ops)
                if (numKeys > 0) {
                    val selectedKeys = selector.selectedKeys()
                    val keyStream = selectedKeys.parallelStream()
                    keyStream.forEach {
                        if (it.isReadable && it.isValid) {
                            readFromProxy()
                        }
                        if (it.isWritable && it.isValid) {
                            if (outgoingQueue.isNotEmpty()) {
                                val buffer = outgoingQueue.take()
                                while (buffer.hasRemaining()) {
                                    datagramChannel.write(buffer)
                                }
                            } else {
                                it.interestOps(OP_READ)
                            }
                        }
                    }
                    selectedKeys.clear()
                }
            } catch (e: Exception) {
                logger.warn("Exception on select, probably shutting down: $e")
                break
            }
        }
        selectorJob.complete()
    }

    private fun readFromProxy() {
        val recvBuffer = ByteBuffer.allocate(MAX_RECEIVE_BUFFER_SIZE)
        datagramChannel.read(recvBuffer)
        recvBuffer.flip()

        fromProxyStream.put(recvBuffer)
        fromProxyStream.flip()

        val packets = parseStream(fromProxyStream)
        for (packet in packets) {
            if (packet is SentinelPacket) {
                logger.debug("Sentinel packet, skip")
                continue
            }
            logger.debug("From proxy: $packet")
            packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = EtherType.DETECT)
            tunWrite(packet.toByteArray())
        }
    }

    private fun readFromTunWriteToProxy() {
        val readBuffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)
        val filters = onlyProtocols.isNotEmpty() || onlyDestinations.isNotEmpty()

        if (filters) {
            logger.warn("Filters enabled, not sending all packets to proxy")
        }

        while (isRunning.get()) {
            val bytesToRead = min(MAX_RECEIVE_BUFFER_SIZE, stream.remaining())
            val bytesRead =
                try {
                    tunRead(readBuffer, bytesToRead)
                } catch (e: Exception) {
                    logger.warn("Exception trying to read from proxy, probably shutting down: $e")
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

                var numPackets = 0
                if (filters) {
                    for (packet in packets) {
                        if (onlyDestinations.isNotEmpty()) {
                            if (packet.ipHeader?.destinationAddress in onlyDestinations) {
                                if (onlyProtocols.isNotEmpty()) {
                                    if (packet.ipHeader?.protocol in onlyProtocols) {
                                        outgoingQueue.add(ByteBuffer.wrap(packet.toByteArray()))
                                        numPackets++
                                        // logger.debug("To proxy: $packet")
                                    }
                                } else {
                                    outgoingQueue.add(ByteBuffer.wrap(packet.toByteArray()))
                                    numPackets++
                                    // logger.debug("To proxy: $packet")
                                }
                            }
                        } else {
                            if (onlyProtocols.isNotEmpty()) {
                                if (packet.ipHeader?.protocol in onlyProtocols) {
                                    outgoingQueue.add(ByteBuffer.wrap(packet.toByteArray()))
                                    numPackets++
                                    // logger.debug("To proxy: $packet")
                                }
                            }
                        }
                    }
                } else {
                    for (packet in packets) {
                        outgoingQueue.add(ByteBuffer.wrap(packet.toByteArray()))
                        numPackets++
                    }
                }
                if (numPackets > 0) {
                    // logger.debug("Added packets, switching to WRITE mode")
                    synchronized(changeRequests) {
                        changeRequests.add(ChangeRequest(datagramChannel, CHANGE_OPS, OP_WRITE))
                    }
                    selector.wakeup()
                }
            }
        }

        logger.warn("No longer reading from TUN adapter")
        readFromTunJob.complete()
    }

    open fun stop() {
        if (isRunning.get().not()) {
            logger.warn("Trying to stop when we're not running")
            return
        }
        logger.debug("Stopping client")
        isRunning.set(false)
        selector.close()
        try {
            datagramChannel.close()
        } catch (e: Exception) {
            logger.warn("Error closing datagram channel: $e")
        }
        runBlocking {
            logger.debug("Waiting for tun reader to stop")
            readFromTunJob.join()
            logger.debug("Stopped, waiting for selector job to stop")
            selectorJob.join()
            logger.debug("Stopped")
        }
        logger.debug("Client stopped")
    }
}
