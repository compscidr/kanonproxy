package com.jasonernst.kanonproxy

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.takeWhile
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import kotlin.math.min

class BidirectionalByteChannel : ByteChannel {
    private val buffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    private var isOpen = true
    private val readyToRead = MutableStateFlow(false)
    private val mutex = Mutex()

    override fun isOpen(): Boolean = isOpen

    override fun close() {
        this.isOpen = false
        readyToRead.value = true
    }

    override fun write(src: ByteBuffer): Int {
        return runBlocking {
            mutex.withLock {
                val availableBytes = min(buffer.remaining(), src.remaining())
                buffer.put(src.array(), src.position(), availableBytes)
                src.position(src.position() + availableBytes)
                readyToRead.value = true
                return@runBlocking availableBytes
            }
        }
    }

    override fun read(dst: ByteBuffer): Int {
        return runBlocking {
            mutex.withLock {
                // when this function is called, we expect the buffer is pointing to the end of what was written to it
                // if its at zero, there is nothing to read
                if (buffer.position() == 0) {
                    runBlocking {
                        readyToRead.takeWhile { !it }.collect {}
                    }
                }
                if (!isOpen) {
                    return@runBlocking 0
                }
                // flip the buffer to get it from write mode to read mode
                buffer.flip()
                val availableBytes = min(buffer.remaining(), dst.remaining())
                dst.put(buffer.array(), buffer.position(), availableBytes)
                buffer.position(buffer.position() + availableBytes)
                if (!buffer.hasRemaining()) {
                    readyToRead.value = false
                }
                // compact to get us back into read mode
                buffer.compact()
                return@runBlocking availableBytes
            }
        }
    }

    fun available(): Int =
        if (readyToRead.value.not()) {
            0
        } else {
            buffer.position() // because we haven't flipped yet, this will be how many bytes there are to read
        }
}
