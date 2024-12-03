package com.jasonernst.kanonproxy

import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import kotlin.math.min

class BidirectionalByteChannel : ByteChannel {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val buffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    private var isOpen = true
    // private val readyToRead = MutableStateFlow(false)

    override fun isOpen(): Boolean = isOpen

    override fun close() {
        this.isOpen = false
        // readyToRead.value = true
    }

    override fun write(src: ByteBuffer): Int {
        logger.debug("Waiting to write: ${src.limit()} bytes")
        synchronized(buffer) {
            val availableBytes = min(buffer.remaining(), src.remaining())
            buffer.put(src.array(), src.position(), availableBytes)
            src.position(src.position() + availableBytes)
            // readyToRead.value = true
            logger.debug("Wrote $availableBytes bytes")
            return availableBytes
        }
    }

    override fun read(dst: ByteBuffer): Int {
        // when this function is called, we expect the buffer is pointing to the end of what was written to it
        // if its at zero, there is nothing to read
//        if (buffer.position() == 0) {
//            runBlocking {
//                readyToRead.takeWhile { !it }.collect {}
//            }
//        }
        if (!isOpen) {
            return 0
        }

        synchronized(buffer) {
            // flip the buffer to get it from write mode to read mode
            buffer.flip()
            val availableBytes = min(buffer.remaining(), dst.remaining())
            dst.put(buffer.array(), buffer.position(), availableBytes)
            buffer.position(buffer.position() + availableBytes)
//        if (!buffer.hasRemaining()) {
//            readyToRead.value = false
//        }
            // compact to get us back into read mode
            buffer.compact()
            return availableBytes
        }
    }

    fun available(): Int =
//        if (readyToRead.value.not()) {
//            0
//        } else {
//            buffer.position() // because we haven't flipped yet, this will be how many bytes there are to read
//        }
        synchronized(buffer) {
            return buffer.position()
        }
}
