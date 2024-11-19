package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet
import java.net.InetSocketAddress

interface SessionManager {
    fun removeSession(session: Session)

    fun handlePackets(
        packets: List<Packet>,
        clientAddress: InetSocketAddress,
    )
}
