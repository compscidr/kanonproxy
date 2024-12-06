package com.jasonernst.kanonproxy.ui

interface VpnUiService {
    fun startVPN()
    fun stopVPN()
    fun startPcapServer()
    fun stopPcapServer()
}