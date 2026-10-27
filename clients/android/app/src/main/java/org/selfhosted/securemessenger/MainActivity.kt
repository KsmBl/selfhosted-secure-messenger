package org.selfhosted.securemessenger

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.LaunchedEffect
import org.unifiedpush.android.connector.UnifiedPush
import androidx.activity.viewModels

class MainActivity : ComponentActivity() {
    private val model: AppModel by viewModels()
    private val admin: AdminModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        // System bar icons follow the light/dark mode.
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // No screenshots, no previews in the recent-apps list (FR-014). Only
        // debug builds started with `--ez ssm.allowScreenshots true` (UI
        // testing) skip this; release builds always set it.
        val allowScreenshots = BuildConfig.DEBUG && intent.getBooleanExtra("ssm.allowScreenshots", false)
        if (!allowScreenshots) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent {
            LaunchedEffect(model.wantsPushRegistration) {
                if (model.wantsPushRegistration) registerPush()
            }
            App(model, admin, onAllowBackground = ::allowBackgroundConnection)
        }
        requestPermissions()
    }

    private val permissionRequest =
        registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { }

    /**
     * Notifications (Android 13+) and local network access (Android 17+;
     * without it a server on the home network is unreachable).
     */
    private fun requestPermissions() {
        val wanted = buildList {
            if (Build.VERSION.SDK_INT >= 33) add(Manifest.permission.POST_NOTIFICATIONS)
            if (Build.VERSION.SDK_INT >= 37) add("android.permission.ACCESS_LOCAL_NETWORK")
        }.filter { checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED }
        if (wanted.isNotEmpty()) permissionRequest.launch(wanted.toTypedArray())
    }

    override fun onStart() {
        super.onStart()
        AppVisibility.foreground = true
        model.returnedFromPicker()
        // Without a push app, a background connection delivers notifications.
        ConnectionService.update(this)
        model.pushAvailable = ConnectionService.pushAppInstalled(this)
        model.batteryRestricted = !model.pushAvailable && ConnectionService.batteryOptimized(this)
    }

    /** Asks Android to keep the background connection alive in deep sleep. */
    fun allowBackgroundConnection() {
        startActivity(
            Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:$packageName")),
        )
    }

    /**
     * UnifiedPush (ADR-0008): uses the distributor the user picked (e.g. ntfy)
     * or the default one; without any, background notifications are off.
     */
    private fun registerPush() {
        UnifiedPush.tryUseCurrentOrDefaultDistributor(this) { available ->
            if (available) UnifiedPush.register(this) else model.pushAvailable = false
            ConnectionService.update(this)
        }
    }

    /** Leaving the app locks it: keys and decrypted messages leave memory (FR-013). */
    override fun onStop() {
        super.onStop()
        AppVisibility.foreground = false
        if (!isChangingConfigurations && model.pickerOpenedAt == 0L) {
            admin.clear()
            model.lock()
        }
    }
}
