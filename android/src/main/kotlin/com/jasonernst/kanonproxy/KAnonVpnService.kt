package com.jasonernst.kanonproxy

import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import androidx.preference.PreferenceManager
import com.jasonernst.icmp.android.IcmpAndroid
import com.jasonernst.kanonproxy.model.KAnonViewModel
import com.jasonernst.kanonproxy.ui.VpnUiService
import com.jasonernst.packetdumper.serverdumper.ConnectedUsersChangedCallback
import com.jasonernst.packetdumper.serverdumper.PcapNgTcpServerPacketDumper
import org.slf4j.LoggerFactory

class KAnonVpnService: VpnService(), VpnUiService, ConnectedUsersChangedCallback {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val binder = LocalBinder()

    private val packetDumper = PcapNgTcpServerPacketDumper(callback = this, isSimple = false)
    private lateinit var viewModel: KAnonViewModel

    private val server = Server(IcmpAndroid)
    private lateinit var client: AndroidClient
    private lateinit var vpnFileDescriptor: ParcelFileDescriptor

    /**
     * Class used for the client Binder. Because we know this service always
     * runs in the same process as its clients, we don't need to deal with IPC.
     */
    inner class LocalBinder : Binder() {
        // Return this instance of LocalService so clients can call public methods.
        fun getService(): KAnonVpnService = this@KAnonVpnService
    }

    companion object {
        private const val VPN_ADDRESS = "10.10.19.2"
        private const val VPN_SUBNET_MASK = 24
        private const val VPN6_ADDRESS = "fd00:10:10:19::2"
        private const val VPN_SUBNET6_MASK = 64
        private const val DNS_SERVER = "8.8.8.8"
        private const val DNS6_SERVER = "2001:4860:4860::8888"
        private const val MAX_STREAM_BUFFER_SIZE = 1048576 // max we can write into the stream without parsing
        private const val MAX_RECEIVE_BUFFER_SIZE = 1500   // max amount we can recv in one read (should be the MTU or bigger probably)
    }

    override fun startVPN() {
        // todo: put an atomic boolean here to prevent multiple starts

        server.start()

        val builder = Builder()
            .addAddress(VPN_ADDRESS, VPN_SUBNET_MASK)
            //.addAddress(VPN6_ADDRESS, VPN_SUBNET6_MASK)
            .addDnsServer(DNS_SERVER)
            //.addDnsServer(DNS6_SERVER)
            .setMtu(MAX_RECEIVE_BUFFER_SIZE)
            .addRoute("0.0.0.0", 0)
        //.addRoute("2000::", 3) // https://wiki.strongswan.org/issues/1261

        vpnFileDescriptor = builder.establish() ?: throw RuntimeException("Error establishing VPN")
        client = AndroidClient(vpnFileDescriptor = vpnFileDescriptor)
        client.connect()
        viewModel.serviceStarted()
    }

    override fun stopVPN() {
        vpnFileDescriptor.close()
        server.stop()
        client.close()
        viewModel.serviceStopped()
    }

    override fun startPcapServer() {
        packetDumper.start()
        viewModel.pcapServerStarted()
    }

    override fun stopPcapServer() {
        packetDumper.stop()
        viewModel.pcapServerStopped()
    }

    override fun onBind(intent: Intent): IBinder? {
        logger.debug("ON BIND CALLED")
        return binder
    }

    override fun onUnbind(intent: Intent): Boolean {
        logger.debug("ON UNBIND CALLED")
        // All clients have unbound with unbindService()
        return super.onUnbind(intent)
    }

    override fun onCreate() {
        logger.debug("ON CREATE CALLED")
        viewModel = KAnonViewModel.getInstance(PreferenceManager.getDefaultSharedPreferences(applicationContext))
    }

    override fun onConnectedUsersChanged(connectedUsers: List<String>) {
        logger.debug("Connected users changed: {}", connectedUsers)
        viewModel.pcapUsersChanged(connectedUsers)
    }
}