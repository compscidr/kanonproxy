package com.jasonernst.kanonproxy

import java.nio.channels.spi.AbstractSelectableChannel

// https://rox-xmlrpc.sourceforge.net/niotut/
data class ChangeRequest(
    val channel: AbstractSelectableChannel,
    val type: Int,
    val ops: Int,
) {
    companion object {
        const val REGISTER = 1
        const val CHANGE_OPS = 2
    }
}
