package com.jasonernst.kanonproxy.tuntap

import com.jasonernst.kanonproxy.ChangeRequest
import com.jasonernst.kanonproxy.ChangeRequest.Companion.CHANGE_OPS
import com.jasonernst.kanonproxy.ChangeRequest.Companion.REGISTER
import com.sun.jna.Native
import com.sun.jna.NativeLong
import jnr.enxio.channels.NativeSelectorProvider
import jnr.enxio.channels.NativeSocketChannel
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey.OP_READ
import java.nio.channels.SelectionKey.OP_WRITE
import java.nio.channels.Selector
import java.util.LinkedList
import java.util.concurrent.LinkedBlockingDeque
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.experimental.or
import kotlin.math.min

/**
 * Note: with the linux tun/tap device, we could probably add the channel to the selector directly
 * in the client and use a single thread, however, the Android tun/tap doesn't easily adapt to a
 * SelectableChannel which is why I'm doing things this way.
 */
class TunTapDevice {
    companion object {
        // the function call for configuring a TUN interface in ioctl from if_tun.h
        private val TUN_SET_IFF = NativeLong(0x400454caL)
        private const val O_RDWR = 2 // from fcntl-linux.h
        private const val IFACE_NAME = "kanon"
        private const val DEVICE_TYPE: Short = 0x0001 // 0x0001 for TUN, 0x0002 for TAP

        // from if_tun.h - tells the kernel to not add packet information header before the packet
        private const val FLAGS_IFF_NO_PI: Short = 0x1000

        private const val MAX_RECEIVE_BUFFER_SIZE = 1500 // max amount we can recv in one read (should be the MTU or bigger probably)
    }

    private val logger = LoggerFactory.getLogger(javaClass)
    private lateinit var nativeSocketChannel: NativeSocketChannel

    private val isRunning = AtomicBoolean(false)
    private lateinit var selector: Selector
    private lateinit var selectorJob: CompletableJob
    private lateinit var selectorScope: CoroutineScope
    private val changeRequests = LinkedList<ChangeRequest>()
    private val outgoingQueue = LinkedBlockingDeque<ByteBuffer>() // queue of data to be read
    private val incomingQueue = LinkedBlockingDeque<ByteBuffer>() // queue of data to be written

    fun open() {
        if (isRunning.get()) {
            logger.error("Already opened")
            return
        }
        val fd = LibC.open("/dev/net/tun", O_RDWR)
        if (fd < 0) {
            throw RuntimeException("Error opening TUN/TAP device: $fd ${Native.getLastError()}")
        } else {
            logger.debug("Opened TUN/TAP device: $fd")
        }
        val tunConfigReq = IfReq(flags = (DEVICE_TYPE or FLAGS_IFF_NO_PI), nameString = IFACE_NAME)
        logger.debug("Creating TUN/TAP device: $tunConfigReq")

        // sets the device to a TUN or TAP device with no packet info
        val tunCreateResult = LibC.ioctl(fd, TUN_SET_IFF, tunConfigReq)
        if (tunCreateResult != 0) {
            LibC.close(fd)
            throw RuntimeException("Error creating TUN/TAP device: $tunCreateResult ${Native.getLastError()}")
        }
        logger.debug("Created TUN/TAP device")
        isRunning.set(true)
        nativeSocketChannel = NativeSocketChannel(fd)

        // if we don't put this into non-blocking, it gets stuck on the read even when we try to
        // close, so we use a selector instead
        nativeSocketChannel.configureBlocking(false)

        selector = NativeSelectorProvider.getInstance().openSelector()
        selectorJob = SupervisorJob()
        selectorScope = CoroutineScope(Dispatchers.IO + selectorJob)
        selectorScope.launch {
            selectorLoop()
        }
    }

    private fun selectorLoop() {
        nativeSocketChannel.register(selector, OP_READ)

        while (isRunning.get()) {
            synchronized(changeRequests) {
                for (changeRequest in changeRequests) {
                    when (changeRequest.type) {
                        REGISTER -> {
                            logger.debug("Processing REGISTER: ${changeRequest.ops}")
                            changeRequest.channel.register(selector, changeRequest.ops)
                        }
                        CHANGE_OPS -> {
                            logger.debug("Processing CHANGE_OPS: ${changeRequest.ops}")
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
                            val recvBuffer = ByteBuffer.allocate(MAX_RECEIVE_BUFFER_SIZE)
                            nativeSocketChannel.read(recvBuffer)
                            recvBuffer.flip()
                            outgoingQueue.add(recvBuffer)
                        }
                        if (it.isWritable && it.isValid) {
                            if (incomingQueue.isNotEmpty()) {
                                val buffer = incomingQueue.take()
                                while (buffer.hasRemaining()) {
                                    nativeSocketChannel.write(buffer)
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

    /**
     * This should not be called from multiple threads, or each thread will get different data.
     */
    fun read(
        readBytes: ByteArray,
        bytesToRead: Int,
    ): Int {
        if (isRunning.get().not()) {
            return -1
        }
        // this will block until the selector puts something here, to unblock when we're shutting
        // down, just stick an empty buffer in the outgoing queue
        val buffer = outgoingQueue.take()
        val bytesToTake = min(bytesToRead, buffer.remaining())
        logger.debug(
            "About to read: $bytesToTake bytes from buffer, position: ${buffer.position()}, limit: ${buffer.limit()}, remaining: ${buffer.remaining()}",
        )
        buffer.get(readBytes, 0, bytesToTake)
        return bytesToTake
    }

    fun write(writeBytes: ByteArray) {
        incomingQueue.add(ByteBuffer.wrap(writeBytes))
        synchronized(changeRequests) {
            changeRequests.add(ChangeRequest(nativeSocketChannel, CHANGE_OPS, OP_WRITE))
        }
        selector.wakeup()
    }

    fun close() {
        isRunning.set(false)
        selector.close()
        nativeSocketChannel.close()
        outgoingQueue.put(ByteBuffer.allocate(0)) // unstick any blocking reads
        runBlocking {
            selectorJob.join()
        }
    }
}
