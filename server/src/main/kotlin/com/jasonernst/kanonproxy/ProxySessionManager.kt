package com.jasonernst.kanonproxy

import java.net.InetSocketAddress
import java.nio.ByteBuffer

interface ProxySessionManager {
    fun enqueueOutgoing(
        clientAddress: InetSocketAddress,
        buffer: ByteBuffer,
    )

    fun removeSession(clientAddress: InetSocketAddress)
}
