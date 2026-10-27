package org.selfhosted.securemessenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.unifiedpush.android.connector.UnifiedPush
import uniffi.ssm_ffi.FfiException
import uniffi.ssm_ffi.FfiWake
import uniffi.ssm_ffi.openWatcher
import uniffi.ssm_ffi.profileExists

/**
 * Background connection to the server for notifications when no UnifiedPush
 * app is installed. Keeps a wake-up channel open with the device key alone
 * (works while the app is locked, never sees content) and shows "New message
 * from M…" when the number of waiting messages grows. Android requires a
 * small permanent notification for this.
 */
class ConnectionService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var loop: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val notification = ongoingNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(ONGOING_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_REMOTE_MESSAGING)
        } else {
            startForeground(ONGOING_ID, notification)
        }
        if (loop?.isActive != true) loop = scope.launch { watch() }
        return START_STICKY
    }

    private suspend fun watch() {
        val dir = Sessions.profileDir(this)
        if (!profileExists(dir)) {
            stopSelf()
            return
        }
        val watcher = try {
            openWatcher(dir)
        } catch (e: FfiException) {
            stopSelf()
            return
        }
        var notified = 0L
        var backoff = MIN_BACKOFF_MS
        while (scope.isActive) {
            try {
                when (watcher.nextWake()) {
                    FfiWake.SYNC -> {
                        backoff = MIN_BACKOFF_MS
                        val hint = watcher.notificationHint()
                        // While the app is open it shows the messages itself.
                        if (hint.pendingMessages > notified && !AppVisibility.foreground) {
                            Notifications.showNewMessage(this, hint.senderInitial, hint.pendingMessages)
                        }
                        notified = hint.pendingMessages
                    }
                    FfiWake.RECONNECT -> delay(backoff)
                    FfiWake.INACTIVE -> {
                        stopSelf()
                        return
                    }
                }
            } catch (e: FfiException) {
                // Offline, server down, device still pending: try again later.
                delay(backoff)
                backoff = (backoff * 2).coerceAtMost(MAX_BACKOFF_MS)
            }
        }
    }

    private fun ongoingNotification(): Notification {
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Background connection", NotificationManager.IMPORTANCE_MIN).apply {
                description = "Keeps the connection to your server for new-message notifications. You can hide it here."
                setShowBadge(false)
            },
        )
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL)
            .setSmallIcon(R.drawable.ic_stat_message)
            .setContentTitle("Waiting for new messages")
            .setContentText("Connected to your server")
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "connection"
        private const val ONGOING_ID = 2
        private const val MIN_BACKOFF_MS = 5_000L
        private const val MAX_BACKOFF_MS = 60_000L

        /** Whether a UnifiedPush app (ntfy, …) handles wake-ups instead. */
        fun pushAppInstalled(context: Context): Boolean = UnifiedPush.getDistributors(context).isNotEmpty()

        /** Starts the service when it is needed (an account, no push app), stops it otherwise. */
        fun update(context: Context) {
            val app = context.applicationContext
            val intent = Intent(app, ConnectionService::class.java)
            if (profileExists(Sessions.profileDir(app)) && !pushAppInstalled(app)) {
                app.startForegroundService(intent)
            } else {
                app.stopService(intent)
            }
        }

        /** Without this Android may cut the connection during deep sleep. */
        fun batteryOptimized(context: Context): Boolean =
            !context.getSystemService(PowerManager::class.java).isIgnoringBatteryOptimizations(context.packageName)
    }
}

/** Restarts the background connection after a reboot or an app update. */
class StartReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> ConnectionService.update(context)
        }
    }
}
