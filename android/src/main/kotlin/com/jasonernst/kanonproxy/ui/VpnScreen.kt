package com.jasonernst.kanonproxy.ui

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCompositionContext
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role.Companion.Button
import androidx.compose.ui.unit.dp
import com.jasonernst.kanonproxy.VpnPermissionHelper
import com.jasonernst.kanonproxy.model.KAnonViewModel
import org.slf4j.LoggerFactory

@Composable
fun VpnScreen(kAnonViewModel: KAnonViewModel, vpnUiService: VpnUiService) {
    val context = LocalContext.current

    Column(modifier = Modifier.fillMaxSize()) {
        Row(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(top = 14.dp, start = 24.dp),
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center
            ) {
                Text("Packet Dumper Service")
            }
            Column(
                modifier = Modifier.fillMaxWidth().padding(end = 24.dp),
                horizontalAlignment = androidx.compose.ui.Alignment.End
            ) {
                Switch(
                    checked = kAnonViewModel.isServiceStarted(),
                    onCheckedChange = {
                        if (it) {
                            if (VpnPermissionHelper.isVPNPermissionMissing(context)) {
                                kAnonViewModel.showPermissionScreen()
                            } else {
                                vpnUiService.startVPN()
                            }
                        } else {
                            val logger = LoggerFactory.getLogger("SessionScreen")
                            logger.debug("Stopping service")
                            vpnUiService.stopVPN()
                        }
                    }
                )
            }
        }
        Row {
            Column(
                modifier = Modifier.padding(top = 14.dp, start = 24.dp),
                verticalArrangement = androidx.compose.foundation.layout.Arrangement.Center
            ) {
                Text("Wireshark Pcapng server")
            }
            Column(
                modifier = Modifier.fillMaxWidth().padding(end = 24.dp),
                horizontalAlignment = androidx.compose.ui.Alignment.End
            ) {
                Switch(
                    checked = kAnonViewModel.isPcapServerStarted(),
                    onCheckedChange = {
                        if (it) {
                            vpnUiService.startPcapServer()
                        } else {
                            vpnUiService.stopPcapServer()
                        }
                    }
                )
            }
        }

        LazyColumn {
            items(kAnonViewModel.getPcapUsers()) { pcapUser ->
                PcapUserItem(pcapUser = pcapUser)
            }
        }

        Row {
            val isRunning = kAnonViewModel.isRunning.value
            if (isRunning) {
                Button(onClick = {kAnonViewModel.stopThreadScope()}) {
                    Text("Stop")
                }
            } else {
                Button(onClick = {kAnonViewModel.startThreadScope()}) {
                    Text("Start")
                }
            }
        }
    }
}