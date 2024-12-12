package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import java.net.InetSocketAddress

interface SessionManager {
    fun removeSessionByClientAddress(clientAddress: InetSocketAddress)

    fun removeSession(session: Session)

    fun isRunning(): Boolean

    fun handlePackets(
        packets: List<Packet>,
        clientAddress: InetSocketAddress,
    )
}
