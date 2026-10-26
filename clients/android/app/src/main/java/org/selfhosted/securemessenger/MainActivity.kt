package org.selfhosted.securemessenger

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels

class MainActivity : ComponentActivity() {
    private val model: AppModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // No screenshots, no previews in the recent-apps list (FR-014). Only
        // debug builds started with `--ez ssm.allowScreenshots true` (UI
        // testing) skip this; release builds always set it.
        val allowScreenshots = BuildConfig.DEBUG && intent.getBooleanExtra("ssm.allowScreenshots", false)
        if (!allowScreenshots) {
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        setContent { App(model) }
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

    /** Leaving the app locks it: keys and decrypted messages leave memory (FR-013). */
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            model.lock()
        }
    }
}
