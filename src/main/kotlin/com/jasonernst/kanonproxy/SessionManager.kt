package com.jasonernst.kanonproxy

import com.jasonernst.knet.Packet

interface SessionManager {
    fun removeSession(session: Session)

    fun handlePackets(packets: List<Packet>)
}
