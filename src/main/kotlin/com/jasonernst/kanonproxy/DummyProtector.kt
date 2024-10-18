package com.jasonernst.kanonproxy

import org.slf4j.LoggerFactory
import java.net.DatagramSocket
import java.net.Socket

/**
 * A dummy protector which does nothing, which is what we desire on Linux (or for tests)
 */
object DummyProtector : VpnProtector {
    private val logger = LoggerFactory.getLogger(javaClass)

    init {
        logger.warn("Using Dummy Protector: If you're on Android - you probably don't want this")
    }

    override fun protectSocketFd(socket: Int) {
        // noop
    }

    override fun protectUDPSocket(socket: DatagramSocket) {
        // noop
    }

    override fun protectTCPSocket(socket: Socket) {
        // noop
    }
}
