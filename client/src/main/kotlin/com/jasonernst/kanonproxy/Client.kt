package com.jasonernst.kanonproxy

import com.jasonernst.kanonproxy.tuntap.TunTapDevice
import com.jasonernst.knet.Packet
import com.jasonernst.knet.Packet.Companion.parseStream
import com.jasonernst.knet.SentinelPacket
import com.jasonernst.packetdumper.ethernet.EtherType
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
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

class Client(
    private val socketAddress: InetSocketAddress = InetSocketAddress("127.0.0.1", 8080),
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val socket = DatagramSocket()
    private val tunTapDevice = TunTapDevice()

    private val isConnected = AtomicBoolean(false)

    private val readFromTunJob = SupervisorJob()
    private val readFromTunJobScope = CoroutineScope(Dispatchers.IO + readFromTunJob)
    private val readFromProxyJob = SupervisorJob()
    private val readFromProxyJobScope = CoroutineScope(Dispatchers.IO + readFromProxyJob)

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
        socket.connect(socketAddress)
        println("Connected to server: $socketAddress")
        isConnected.set(true)
        tunTapDevice.open()

        readFromProxyJobScope.launch {
            readFromProxyWriteToTun()
        }

        readFromTunJobScope.launch {
            readFromTunWriteToProxy()
        }

        // block until the read job is finished
        runBlocking {
            readFromProxyJob.join()
            readFromTunJob.join()
        }
    }

    private fun readFromProxyWriteToTun() {
        val buffer = ByteArray(MAX_RECEIVE_BUFFER_SIZE)
        val datagram = DatagramPacket(buffer, buffer.size)
        val stream = ByteBuffer.allocate(MAX_STREAM_BUFFER_SIZE)

        while (isConnected.get()) {
            // logger.debug("Waiting for response from server")
            socket.receive(datagram)
            stream.put(buffer, 0, datagram.length)
            stream.flip()
            val packets = parseStream(stream)
            for (packet in packets) {
                if (packet is SentinelPacket) {
                    logger.debug("Sentinel packet, skip")
                    continue
                }
                logger.debug("From proxy: ${packet}")
                tunTapDevice.write(ByteBuffer.wrap(packet.toByteArray()))
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
            val bytesRead = tunTapDevice.read(readBuffer, bytesToRead)
            if (bytesRead == -1) {
                logger.warn("End of OS stream")
                break
            }
            if (bytesRead > 0) {
                stream.put(readBuffer, 0, bytesRead)
                //logger.debug("Read {} bytes from OS. position: {} remaining {}", bytesRead, stream.position(), stream.remaining())
                stream.flip()
                //logger.debug("After flip: position: {} remaining {}", stream.position(), stream.remaining())
                val packets = parseStream(stream)
                for (packet in packets) {
                    logger.debug("To proxy: ${packet}")
                }
                //logger.debug("After parse: position: {} remaining {}", stream.position(), stream.remaining())
                writePackets(packets)
            }
        }
        logger.warn("No longer reading from TUN adapter")
    }

    fun close() {
        packetDumper.stop()
    }
}
