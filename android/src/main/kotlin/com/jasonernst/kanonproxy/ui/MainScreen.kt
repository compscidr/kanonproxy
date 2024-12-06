package com.jasonernst.kanonproxy.ui

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import com.jasonernst.kanonproxy.VpnPermissionHelper.isVPNPermissionMissing
import com.jasonernst.kanonproxy.model.KAnonViewModel
import org.slf4j.LoggerFactory

@Composable
fun MainScreen(kAnonViewModel: KAnonViewModel, vpnService: VpnUiService) {
    val logger = LoggerFactory.getLogger("MainScreen")
    val context = LocalContext.current

    logger.debug("IN HERE")

    if (kAnonViewModel.isPermissionScreenHidden().not()) {
        if (isVPNPermissionMissing(context = context)) {
            logger.debug("VPN permission missing")
            PermissionScreen(kAnonViewModel)
        } else {
            logger.debug("VPN permission granted")
            VpnScreen(kAnonViewModel, vpnService)
        }
    } else {
        logger.debug("VPN permission screen hidden")
        VpnScreen(kAnonViewModel, vpnService)
    }
}