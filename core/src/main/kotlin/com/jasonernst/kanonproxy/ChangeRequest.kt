package com.jasonernst.kanonproxy

import java.nio.channels.Selector
import java.nio.channels.spi.AbstractSelectableChannel
import java.util.LinkedList
import org.slf4j.LoggerFactory

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

        fun processPendingChanges(selector: Selector, changeRequests: LinkedList<ChangeRequest>) {
            // Process any pending changes
            synchronized(changeRequests) {
                for (changeRequest in changeRequests) {
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
                changeRequests.clear()
            }
        }
    }
}
