package com.jasonernst.kanonproxy

import java.nio.ByteBuffer
import java.nio.channels.ByteChannel
import kotlin.math.min

class BidirectionalByteChannel : ByteChannel {
    private val readBuffer = ByteBuffer.allocate(DEFAULT_BUFFER_SIZE)
    private var isOpen = true

    override fun isOpen(): Boolean = isOpen

    override fun close() {
        this.isOpen = false
    }

    override fun write(src: ByteBuffer): Int {
        val availableBytes = min(readBuffer.remaining(), src.remaining())
        readBuffer.put(src.array(), src.position(), availableBytes)
        src.position(src.position() + availableBytes)
        return availableBytes
    }

    override fun read(dst: ByteBuffer): Int {
        val availableBytes = min(readBuffer.remaining(), dst.remaining())
        readBuffer.flip()
        dst.put(readBuffer.array(), readBuffer.position(), availableBytes)
        readBuffer.position(readBuffer.position() + availableBytes)
        readBuffer.compact()
        return availableBytes
    }
}
