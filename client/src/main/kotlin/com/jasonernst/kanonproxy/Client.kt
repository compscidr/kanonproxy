package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.ChangeRequest.Companion.CHANGE_OPS
import com.jasonernst.kanonproxy.tuntap.TunTapDevice
import com.jasonernst.knet.Packet
import com.jasonernst.knet.Packet.Companion.parseStream
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.CancelledKeyException
import java.nio.channels.ClosedSelectorException
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey.OP_READ
import java.nio.channels.SelectionKey.OP_WRITE
import java.nio.channels.Selector
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

class Client(
    private val socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080),
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val channel = DatagramChannel.open()
    private val tunTapDevice = TunTapDevice()

    private val isConnected = AtomicBoolean(false)

    private val readFromTunJob = SupervisorJob()
    private val readFromTunJobScope = CoroutineScope(Dispatchers.IO + readFromTunJob)

    private val outgoingPackets = ConcurrentLinkedQueue<Packet>()
    private val changeRequests = ConcurrentLinkedQueue<ChangeRequest>()
    private val selector = Selector.open()
    private val readWriteJob = SupervisorJob()
    private val readWriteJobScope = CoroutineScope(Dispatchers.IO + readWriteJob)

    private val packetDumper = PcapNgTcpServerPacketDumper(isSimple = false)

    companion object {
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)

        @JvmStatic
        fun main(args: Array<String>) {
            val client =
                if (args.isEmpty()) {
                    println("Using default server: 127.0.0.1 8080")
                    Client()
                } else {
                    if (args.size != 2) {
                        println("Usage: Client <server> <port>")
                        return
                    }
                    val server = args[0]
                    val port = args[1].toInt()
                    Client(InetSocketAddress(server, port))
                }
            client.connect()
        }
    }

    fun connect() {
        if (isConnected.get()) {
            println("Client is already connected")
            return
        }
        packetDumper.start()

        println("Connecting to server: $socketAddress")
        channel.configureBlocking(false)
        channel.connect(socketAddress)
        println("Connected to server: $socketAddress")
        isConnected.set(true)
        tunTapDevice.open()

        readFromTunJobScope.launch {
            readFromTun()
        }
        channel.register(selector, OP_READ)
        readWriteJobScope.launch {
            readWriteFromProxy()
        }

        // block until the read job is finished
        runBlocking {
            readFromTunJob.join()
            readWriteJob.join()
        }
    }

    private fun readWriteFromProxy() {
        val incomingProxyStream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)
        while (isConnected.get()) {
            ChangeRequest.processPendingChanges(selector, changeRequests)
            val numKeys = selector.select()
            if (numKeys > 0) {
                logger.debug("Select has $numKeys to process")
            }
            try {
                val selectedKeys = selector.selectedKeys()
                if (selectedKeys.size > 0) {
                    logger.warn("SELECT: $selectedKeys")
                }
                val keyStream = selectedKeys.parallelStream()
                keyStream.forEach {
                    if (!it.isValid) {
                        logger.error("INVALID KEY!!!!! $this@Session")
                    } else {
                        val datagramChannel = it.channel() as DatagramChannel
                        if (it.isReadable) {
                            val len = datagramChannel.read(incomingProxyStream)
                            if (len > 0) {
                                incomingProxyStream.flip()
                                val packets = parseStream(incomingProxyStream)
                                for (packet in packets) {
                                    tunTapDevice.write(ByteBuffer.wrap(packet.toByteArray()))
                                    packetDumper.dumpBuffer(ByteBuffer.wrap(packet.toByteArray()), etherType = EtherType.DETECT)
                                }
                            }
                        } else if (it.isWritable) {
                            while (outgoingPackets.isNotEmpty()) {
                                val packet = outgoingPackets.remove()
                                val sendBuffer = ByteBuffer.wrap(packet.toByteArray())
                                datagramChannel.send(sendBuffer, socketAddress)
                                packetDumper.dumpBuffer(sendBuffer, etherType = EtherType.DETECT)
                            }
                            changeRequests.add(ChangeRequest(channel, CHANGE_OPS, OP_READ))
                            selector.wakeup()
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

    private fun readFromTun() {
        val readBuffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isConnected.get()) {
            val bytesToRead = min(MAX_RECEIVE_BUFFER_SIZE, stream.remaining())
            val bytesRead = tunTapDevice.read(readBuffer, bytesToRead)
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
                // logger.debug("After parse: position: {} remaining {}", stream.position(), stream.remaining())
                outgoingPackets.addAll(packets)
                logger.debug("Added ${packets.size} packets to outgoing queue, total: ${outgoingPackets.size}")
                changeRequests.add(ChangeRequest(channel, CHANGE_OPS, OP_WRITE))
                selector.wakeup()
            }
        }
        logger.warn("No longer reading from TUN adapter")
    }

    fun close() {
        packetDumper.stop()
    }
}
