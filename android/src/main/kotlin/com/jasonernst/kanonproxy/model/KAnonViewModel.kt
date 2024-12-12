package com.jasonernst.kanonproxy.model

import android.content.SharedPreferences
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.util.concurrent.atomic.AtomicBoolean

class KAnonViewModel private constructor(private val sharedPreferences: SharedPreferences) : ViewModel() {
    private val logger = LoggerFactory.getLogger(javaClass)
    private val _hidePermissionsScreen = mutableStateOf(sharedPreferences.getBoolean(HIDE_PERMISSION_SCREEN_KEY, false))
    private val _serviceStarted = mutableStateOf(false)
    private val _pcapServerStarted = mutableStateOf(false)
    private val _pcapUsers = mutableStateListOf<String>()
    val isRunning = mutableStateOf(false)
    private lateinit var job: CompletableJob
    private lateinit var scope: CoroutineScope

    companion object {
        private var instance: KAnonViewModel? = null
        const val HIDE_PERMISSION_SCREEN_KEY = "HIDE_PERMISSION_SCREEN"

        fun getInstance(sharedPreferences: SharedPreferences): KAnonViewModel {
            if (instance == null) {
                instance = KAnonViewModel(sharedPreferences)
            }
            return instance as KAnonViewModel
        }
    }

    fun isPermissionScreenHidden(): Boolean {
        return _hidePermissionsScreen.value
    }

    fun hidePermissionScreen() {
        _hidePermissionsScreen.value = true
        sharedPreferences.edit().putBoolean(HIDE_PERMISSION_SCREEN_KEY, true).apply()
    }

    fun showPermissionScreen() {
        _hidePermissionsScreen.value = false
        sharedPreferences.edit().putBoolean(HIDE_PERMISSION_SCREEN_KEY, false).apply()
    }

    fun serviceStarted() {
        _serviceStarted.value = true
    }

    fun serviceStopped() {
        _serviceStarted.value = false
    }

    fun isServiceStarted(): Boolean {
        return _serviceStarted.value
    }

    fun pcapServerStarted() {
        _pcapServerStarted.value = true
    }

    fun pcapServerStopped() {
        _pcapServerStarted.value = false
    }

    fun isPcapServerStarted(): Boolean {
        return _pcapServerStarted.value
    }

    fun pcapUsersChanged(users: List<String>) {
        _pcapUsers.clear()
        _pcapUsers.addAll(users)
    }

    fun getPcapUsers(): List<String> {
        return _pcapUsers
    }

    fun startThreadScope() {
        if (isRunning.value) {
            logger.warn("Already running")
            return
        }
        isRunning.value = true
        job = SupervisorJob()
        scope = CoroutineScope(Dispatchers.IO + job)
        scope.launch {
            Thread.currentThread().name = "TEST"
            var counter = 0L
            while(isRunning.value) {
                if (counter + 1 > Int.MAX_VALUE) {
                    counter = 0
                } else {
                    counter++
                }
            }
            logger.debug("Done waiting")
            job.complete()
        }
    }

    fun stopThreadScope() {
        if (isRunning.value.not()) {
            logger.warn("Trying to stop when not running")
            return
        }
        isRunning.value = false
        runBlocking {
            job.join()
        }
    }
}