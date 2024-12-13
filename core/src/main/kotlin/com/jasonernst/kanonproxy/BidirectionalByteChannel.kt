package com.jasonernst.kanonproxy

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class BidirectionalByteChannel(
    private var buffer: ByteBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE),
) : ByteChannel {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val readyToRead = MutableStateFlow(false)
    private val lock = ReentrantLock()

    override fun isOpen(): Boolean = true

    override fun close() {
        // No resources to free in this simple implementation
    }

    override fun read(dst: ByteBuffer): Int {
        if (!isOpen()) {
            throw IllegalStateException("Channel is closed")
        }

        val needToWait =
            lock.withLock {
                buffer.position() == 0
            }
        if (needToWait) {
            runBlocking {
                readyToRead.takeWhile { !it }.collect {}
            }
        }

        return lock.withLock {
            if (buffer.position() == 0) {
                // its possible since becoming unlocked that something has written again, if so try again
                return 0
            }
            logger.debug("before flip position: ${buffer.position()} limit: ${buffer.limit()} remaining: ${buffer.remaining()}")
            buffer.flip()
            logger.debug("after flip position: ${buffer.position()} limit: ${buffer.limit()} remaining: ${buffer.remaining()}")

            // Check how many bytes can be read
            val bytesToRead = minOf(dst.remaining(), buffer.remaining())
            if (bytesToRead == 0) {
                logger.debug("No space in dst")
                return@withLock 0 // no space in the dst buffer
            }

            dst.put(buffer.array(), 0, bytesToRead)
            buffer.position(bytesToRead)
            buffer.compact()

            bytesToRead
        }
    }

    override fun write(src: ByteBuffer): Int {
        if (!isOpen()) {
            throw IllegalStateException("Channel is closed")
        }

        logger.debug("Waiting for write lock")
        return lock.withLock {
            // Check how many bytes can be written
            val bytesToWrite = minOf(src.remaining(), buffer.capacity() - buffer.position())
            if (bytesToWrite == 0) {
                logger.debug("buffer is full")
                return@withLock 0 // Buffer is full
            }
            logger.debug("before write position: ${buffer.position()} limit: ${buffer.limit()} remaining: ${buffer.remaining()}")
            buffer.put(src.array(), src.position(), bytesToWrite)
            src.position(src.position() + bytesToWrite)
            logger.debug("after write position: ${buffer.position()} limit: ${buffer.limit()} remaining: ${buffer.remaining()}")
            readyToRead.value = true
            bytesToWrite
        }
    }

    fun available(): Int =
        lock.withLock {
            buffer.remaining()
        }

    fun getBuffer(): ByteBuffer =
        lock.withLock {
            // Return a copy of the current buffer state
            buffer.asReadOnlyBuffer()
        }

    fun resetBuffer() {
        lock.withLock {
            // Reset the buffer for reuse
            buffer.clear()
        }
    }
}
