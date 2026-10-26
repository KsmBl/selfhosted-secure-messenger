package org.selfhosted.securemessenger

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
    }

    /** Leaving the app locks it: keys and decrypted messages leave memory (FR-013). */
    override fun onStop() {
        super.onStop()
        if (!isChangingConfigurations) {
            model.lock()
        }
    }
}
