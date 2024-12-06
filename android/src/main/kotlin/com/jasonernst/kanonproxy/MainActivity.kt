package com.jasonernst.kanonproxy

import android.content.ComponentName
import android.content.Intent
import android.content.ServiceConnection
import android.os.Binder
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.preference.PreferenceManager
import com.jasonernst.kanonproxy.model.KAnonViewModel
import com.jasonernst.kanonproxy.ui.MainScreen
import org.slf4j.LoggerFactory

class MainActivity: ComponentActivity() {
    private val logger = LoggerFactory.getLogger(javaClass)
    // example of this pattern: https://github.com/JustAmalll/Stopwatch/blob/master/app/src/main/java/dev/amal/stopwatch/MainActivity.kt
    // more details: https://developer.android.com/develop/background-work/services/bound-services#bind-started-service
    private lateinit var vpnService: KAnonVpnService
    private var isBound by mutableStateOf(false)

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(className: ComponentName?, service: IBinder?) {
            logger.debug("Bound to VPN service")
            // We've bound to LocalService, cast the IBinder and get LocalService instance.
            val binder = service as KAnonVpnService.LocalBinder
            vpnService = binder.getService()
            isBound = true
        }

        override fun onServiceDisconnected(arg0: ComponentName) {
            isBound = false
        }
    }

    /**
     * If we try to use an unbound service, as soon as we call establish on the VPN service we are
     * no longer able to have it stop with stopService. I have a feeling it's because under the hood
     * the VPN service is actually a bound service once we call establish, so we need to bind to it
     * in order to stop it correctly.
     */
    override fun onStart() {
        logger.debug("activity onStart")
        super.onStart()
        Intent(this, KAnonVpnService::class.java).also { intent ->
            logger.debug("binding to VPN service")
            val result = bindService(intent, connection, BIND_AUTO_CREATE)
            logger.debug("bindService result: $result")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        logger.debug("activity onCreate")
        super.onCreate(savedInstanceState)
        val viewModel = KAnonViewModel.getInstance(PreferenceManager.getDefaultSharedPreferences(applicationContext))

        setContent {
            MaterialTheme {
                if (isBound) {
                    MainScreen(viewModel, vpnService)
                }
            }
        }
    }
}