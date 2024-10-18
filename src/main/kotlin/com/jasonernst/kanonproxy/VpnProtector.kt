package com.jasonernst.kanonproxy

import java.net.DatagramSocket
import java.net.Socket

/**
 * Used on Android to mark sockets as "protected" from the VPN, ie) they won't route back
 * into the VPN in a loop.
 */
interface VpnProtector {
    fun protectSocketFd(socket: Int)

    fun protectUDPSocket(socket: DatagramSocket)

    fun protectTCPSocket(socket: Socket)
}
