package com.jasonernst.kanonproxy.model

import android.content.SharedPreferences
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.lifecycle.ViewModel

class KAnonViewModel private constructor(private val sharedPreferences: SharedPreferences) : ViewModel() {
    private val _hidePermissionsScreen = mutableStateOf(sharedPreferences.getBoolean(HIDE_PERMISSION_SCREEN_KEY, false))
    private val _serviceStarted = mutableStateOf(false)
    private val _pcapServerStarted = mutableStateOf(false)
    private val _pcapUsers = mutableStateListOf<String>()

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
}