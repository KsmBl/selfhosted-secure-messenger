package org.selfhosted.securemessenger

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import uniffi.ssm_ffi.SsmSession
import uniffi.ssm_ffi.openProfile
import uniffi.ssm_ffi.profileExists

/**
 * One session per process, shared by the UI and the push service (the
 * profile is locked against a second opener).
 */
object Sessions {
    @Volatile
    private var session: SsmSession? = null

    fun profileDir(context: Context): String =
        context.applicationContext.noBackupFilesDir.resolve("profile").absolutePath

    @Synchronized
    fun get(context: Context): SsmSession? {
        session?.let { return it }
        val dir = profileDir(context)
        if (!profileExists(dir)) return null
        return openProfile(dir).also { session = it }
    }

    @Synchronized
    fun set(newSession: SsmSession) {
        session = newSession
    }
}

/** Whether the UI is visible; push notifications are only shown otherwise. */
object AppVisibility {
    @Volatile
    var foreground = false
}

object Notifications {
    private const val CHANNEL = "messages"
    private const val ID = 1

    /** FR-015: no content, at most the sender's initial. */
    fun showNewMessage(context: Context, senderInitial: String?) {
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "Messages", NotificationManager.IMPORTANCE_HIGH).apply {
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
            },
        )
        val open = PendingIntent.getActivity(
            context, 0,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(android.R.drawable.ic_dialog_email)
            .setContentTitle("New message")
            .setContentText(senderInitial?.let { "From $it…" } ?: "")
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()
        manager.notify(ID, notification)
    }
}

/**
 * Receives content-free wake-ups from the UnifiedPush distributor. Works
 * without the UI and while locked: only the device key is used.
 */
class PushServiceImpl : PushService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        val session = Sessions.get(this) ?: return
        scope.launch { runCatching { session.setPushEndpoint("unifiedpush", endpoint.url) } }
    }

    override fun onMessage(message: PushMessage, instance: String) {
        if (AppVisibility.foreground) return
        val session = Sessions.get(this) ?: return
        val context = applicationContext
        scope.launch {
            val hint = runCatching { session.notificationHint() }.getOrNull() ?: return@launch
            if (hint.pendingMessages > 0) Notifications.showNewMessage(context, hint.senderInitial)
        }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {}

    override fun onUnregistered(instance: String) {}
}
