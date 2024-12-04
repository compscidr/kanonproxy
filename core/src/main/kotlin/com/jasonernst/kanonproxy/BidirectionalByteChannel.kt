package com.jasonernst.kanonproxy

import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

class BidirectionalByteChannel(private var buffer: ByteBuffer = ByteBuffer.allocate(1024)) : ByteChannel {
    private val lock = ReentrantLock()

    override fun isOpen(): Boolean {
        return true
    }

    override fun close() {
        // No resources to free in this simple implementation
    }

    override fun read(dst: ByteBuffer): Int {
        if (!isOpen()) {
            throw IllegalStateException("Channel is closed")
        }

        return lock.withLock {
            // Check how many bytes can be read
            val bytesToRead = minOf(dst.remaining(), buffer.remaining())
            if (bytesToRead == 0) {
                return@withLock -1 // End of stream
            }

            // Read bytes into destination buffer
            for (i in 0 until bytesToRead) {
                dst.put(buffer.get())
            }

            bytesToRead
        }
    }

    override fun write(src: ByteBuffer): Int {
        if (!isOpen()) {
            throw IllegalStateException("Channel is closed")
        }

        return lock.withLock {
            // Check how many bytes can be written
            val bytesToWrite = minOf(src.remaining(), buffer.capacity() - buffer.position())
            if (bytesToWrite == 0) {
                return@withLock 0 // Buffer is full
            }

            // Write bytes from source buffer
            for (i in 0 until bytesToWrite) {
                buffer.put(src.get())
            }

            bytesToWrite
        }
    }

    fun available(): Int {
        return lock.withLock {
            buffer.remaining()
        }
    }

    fun getBuffer(): ByteBuffer {
        return lock.withLock {
            // Return a copy of the current buffer state
            buffer.asReadOnlyBuffer()
        }
    }

    fun resetBuffer() {
        lock.withLock {
            // Reset the buffer for reuse
            buffer.clear()
        }
    }

}
