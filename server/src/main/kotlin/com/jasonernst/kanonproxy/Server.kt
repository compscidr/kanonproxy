package com.jasonernst.kanonproxy

import com.jasonernst.icmp.linux.IcmpLinux
import com.jasonernst.kanonproxy.ChangeRequest.Companion.CHANGE_OPS
import com.jasonernst.kanonproxy.KAnonProxy.Companion.MAX_RECEIVE_BUFFER_SIZE
import com.jasonernst.knet.Packet
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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean

class Server(
    private val port: Int = 8080,
) {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val datagramChannel = DatagramChannel.open()
    private val isRunning = AtomicBoolean(false)
    private val kAnonProxy = KAnonProxy(IcmpLinux)
    private val sessions = ConcurrentHashMap<InetSocketAddress, ProxySession>()

    private val changeRequests = ConcurrentLinkedQueue<ChangeRequest>()
    private val selector = Selector.open()
    private val readFromClientJob = SupervisorJob()
    private val readFromClientJobScope = CoroutineScope(Dispatchers.IO + readFromClientJob)
    private val outgoingClientPackets = ConcurrentLinkedQueue<OutgoingClientPacket>()

    companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            val server =
                if (args.isEmpty()) {
                    println("Using default port: 8080")
                    Server()
                } else {
                    if (args.size != 1) {
                        println("Usage: Server <port>")
                        return
                    }
                    val port = args[0].toInt()
                    Server(port)
                }
            server.start()
        }
    }

    fun start() {
        if (isRunning.get()) {
            println("Server is already running")
            return
        }
        println("Starting server on port: $port")
        datagramChannel.configureBlocking(false)
        datagramChannel.register(selector, OP_READ)
        datagramChannel.bind(InetSocketAddress(port))
        isRunning.set(true)
        kAnonProxy.start()
        readFromClientJobScope.launch {
            readFromClientWriteToProxy()
        }

        runBlocking {
            readFromClientJob.join()
        }
    }

    private fun readFromClientWriteToProxy() {
        val readBuffer = ByteBuffer.allocate(MAX_RECEIVE_BUFFER_SIZE)
        while (isRunning.get()) {
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
                            // we use a local temp buffer first, until we can lookup the session stream so that each
                            // client has its own stream in the case of partial writes so that we don't mixup data
                            // into another client stream.
                            readBuffer.clear()
                            val clientAddress = datagramChannel.receive(readBuffer) as InetSocketAddress
                            val session =
                                sessions.getOrPut(clientAddress) {
                                    val session = ProxySession(clientAddress, kAnonProxy, this)
                                    session.start()
                                    session
                                }
                            readBuffer.flip()
                            while (readBuffer.hasRemaining()) {
                                session.incomingProxyStream.put(readBuffer)
                            }
                            readBuffer.clear()
                            session.incomingProxyStream.flip()
                            val packets = Packet.parseStream(session.incomingProxyStream)
                            kAnonProxy.handlePackets(packets, clientAddress)
                        } else if (it.isWritable) {
                            while (outgoingClientPackets.isNotEmpty()) {
                                val outgoingClientPacket = outgoingClientPackets.remove()
                                val buffer = ByteBuffer.wrap(outgoingClientPacket.packet.toByteArray())
                                datagramChannel.send(buffer, outgoingClientPacket.address)
                            }
                            changeRequests.add(ChangeRequest(datagramChannel, CHANGE_OPS, OP_READ))
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

    fun enqueuePackets(list: List<OutgoingClientPacket>) {
        outgoingClientPackets.addAll(list)
        changeRequests.add(ChangeRequest(datagramChannel, CHANGE_OPS, OP_WRITE))
        selector.wakeup()
    }

    fun stop() {
        isRunning.set(false)
        datagramChannel.close()
        kAnonProxy.stop()
        sessions.values.forEach { it.stop() }
    }
}
