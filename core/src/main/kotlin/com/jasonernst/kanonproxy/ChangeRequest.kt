package com.jasonernst.kanonproxy

import org.slf4j.LoggerFactory
import java.nio.channels.Selector
import java.nio.channels.spi.AbstractSelectableChannel
import java.util.concurrent.ConcurrentLinkedQueue

// https://rox-xmlrpc.sourceforge.net/niotut/
data class ChangeRequest(
    val channel: AbstractSelectableChannel,
    val type: Int,
    val ops: Int,
) {
    companion object {
        private val logger = LoggerFactory.getLogger(ChangeRequest::class.java)
        const val REGISTER = 1
        const val CHANGE_OPS = 2

        fun processPendingChanges(
            selector: Selector,
            changeRequests: ConcurrentLinkedQueue<ChangeRequest>,
        ) {
            // Process any pending changes
            while (changeRequests.isNotEmpty()) {
                val changeRequest = changeRequests.remove()
                when (changeRequest.type) {
                    REGISTER -> {
                        logger.debug("Processing REGISTER")
                        changeRequest.channel.register(selector, changeRequest.ops)
                    }
                    CHANGE_OPS -> {
                        logger.debug("Processing CHANGE_OPS")
                        val key = changeRequest.channel.keyFor(selector)
                        key.interestOps(changeRequest.ops)
                    }
                }
            }
        }
    }
}
