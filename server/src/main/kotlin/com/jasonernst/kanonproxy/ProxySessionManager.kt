package com.jasonernst.kanonproxy

import java.net.InetSocketAddress

interface ProxySessionManager {
    fun removeSession(clientAddress: InetSocketAddress)
}
