package org.selfhosted.securemessenger

import android.app.Application
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.os.Build
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.ssm_ffi.FfiConversation
import uniffi.ssm_ffi.FfiException
import uniffi.ssm_ffi.FfiMessage
import uniffi.ssm_ffi.FfiUpdate
import uniffi.ssm_ffi.SsmSession
import uniffi.ssm_ffi.enroll
import uniffi.ssm_ffi.profileExists

sealed interface Screen {
    data object Setup : Screen
    data class Pending(val fingerprint: String) : Screen
    data object Unlock : Screen
    data object Conversations : Screen
    data class Chat(val conversation: FfiConversation) : Screen
    data object Admin : Screen
}

/**
 * App state. Decrypted messages exist only in [messages] for the open chat
 * and are dropped when the chat is left or the app is locked (FR-013).
 */
class AppModel(application: Application) : AndroidViewModel(application) {
    private val profileDir = Sessions.profileDir(application)
    private val session: SsmSession? get() = Sessions.get(getApplication())
    private var poller: Job? = null

    var screen by mutableStateOf<Screen>(if (profileExists(profileDir)) Screen.Unlock else Screen.Setup)
        private set
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
    var username by mutableStateOf<String?>(null)
        private set
    val conversations = mutableStateListOf<FfiConversation>()
    val messages = mutableStateListOf<FfiMessage>()
    var olderCursor by mutableStateOf<Long?>(null)
        private set
    val unread = mutableStateListOf<String>()

    /** Decrypted image previews of the open chat, by message id; dropped with [messages]. */
    val previews = mutableStateMapOf<String, ImageBitmap>()
    private val previewsRequested = HashSet<String>()

    /**
     * When our own file picker (attach / save) was opened, in elapsedRealtime
     * millis; 0 if none. The system picker stops the activity, which would
     * otherwise lock the app before the result arrives.
     */
    var pickerOpenedAt = 0L

    /** Locks when returning from a picker that stayed open too long (user walked away). */
    fun returnedFromPicker() {
        val opened = pickerOpenedAt
        pickerOpenedAt = 0L
        if (opened != 0L && android.os.SystemClock.elapsedRealtime() - opened > PICKER_GRACE_MS) lock()
    }

    /** An opened image (decrypted original), shown full screen; in memory only. */
    var viewer by mutableStateOf<ImageBitmap?>(null)

    /** False when no UnifiedPush distributor is installed (no background notifications). */
    var pushAvailable by mutableStateOf(true)

    /** The background connection runs but Android may suspend it in deep sleep. */
    var batteryRestricted by mutableStateOf(false)

    /** Set when the account is ready for push registration (done by the activity). */
    var wantsPushRegistration by mutableStateOf(false)

    private fun hardwareSecret(): ByteArray = HardwareSecret.get(getApplication())

    private fun launchBusy(block: suspend () -> Unit) {
        viewModelScope.launch {
            busy = true
            error = null
            try {
                block()
            } catch (e: FfiException) {
                error = e.message ?: e.toString()
                if (e is FfiException.DeviceInactive) lock()
            } catch (e: IOException) {
                error = e.message ?: e.toString()
            } finally {
                busy = false
            }
        }
    }

    fun register(server: String, code: String, withInvite: Boolean, deviceName: String, dots: List<Int>) = launchBusy {
        val secret = hardwareSecret()
        try {
            val newSession = enroll(
                profileDir, server.trim(), code.trim(), withInvite, deviceName.trim(),
                dots.map { it.toByte() }.toByteArray(), secret,
            )
            Sessions.set(newSession)
            screen = Screen.Pending(newSession.fingerprint())
            startPolling()
        } finally {
            secret.fill(0)
        }
    }

    fun unlock(dots: List<Int>) = launchBusy {
        val current = session ?: return@launchBusy
        val wait = current.unlockDelaySecs()
        if (wait > 0uL) {
            error = "Too many wrong patterns. Please wait $wait seconds."
            return@launchBusy
        }
        val secret = hardwareSecret()
        try {
            current.unlock(dots.map { it.toByte() }.toByteArray(), secret)
        } finally {
            secret.fill(0)
        }
        afterUnlock()
    }

    private suspend fun afterUnlock() {
        val current = session ?: return
        username = current.username()
        when (val status = try { current.deviceStatus() } catch (e: FfiException.Network) { "active" }) {
            "active" -> {
                wantsPushRegistration = true
                screen = Screen.Conversations
                refreshConversations()
                startPolling()
            }
            "pending" -> {
                screen = Screen.Pending(current.fingerprint())
                startPolling()
            }
            else -> {
                lock()
                error = "This device was $status by an administrator."
            }
        }
    }

    /** Foreground polling; push wake-ups (UnifiedPush/FCM) follow in phase 8. */
    private fun startPolling() {
        poller?.cancel()
        poller = viewModelScope.launch {
            while (isActive) {
                try {
                    tick()
                } catch (e: FfiException) {
                    if (e is FfiException.DeviceInactive) {
                        lock()
                        error = e.message
                    }
                }
                delay(5_000)
            }
        }
    }

    private suspend fun tick() {
        val current = session ?: return
        when (val s = screen) {
            is Screen.Pending -> if (current.deviceStatus() == "active") afterUnlock()
            is Screen.Conversations, is Screen.Chat -> {
                val updates = current.sync()
                if (updates.isEmpty()) return
                val open = (s as? Screen.Chat)?.conversation?.id
                var reloadChat = false
                for (update in updates) {
                    when (update) {
                        is FfiUpdate.NewMessage ->
                            if (update.conversationId == open) reloadChat = true
                            else if (update.conversationId !in unread) unread.add(update.conversationId)
                        is FfiUpdate.MessageDeleted -> if (update.conversationId == open) reloadChat = true
                        is FfiUpdate.ConversationUpdated -> if (update.conversationId == open) reloadChat = true
                    }
                }
                refreshConversations()
                if (reloadChat && open != null) reloadChat(open)
            }
            else -> {}
        }
    }

    fun refresh() = launchBusy { tick() }

    private suspend fun refreshConversations() {
        val list = session?.conversations() ?: return
        conversations.clear()
        conversations.addAll(list)
        (screen as? Screen.Chat)?.let { chat ->
            list.firstOrNull { it.id == chat.conversation.id }?.let { screen = Screen.Chat(it) }
                ?: closeChat()
        }
    }

    fun openChat(conversation: FfiConversation) = launchBusy {
        clearMedia()
        messages.clear()
        unread.remove(conversation.id)
        screen = Screen.Chat(conversation)
        reloadChat(conversation.id)
    }

    private suspend fun reloadChat(id: String) {
        val page = session?.messages(id, null) ?: return
        messages.clear()
        messages.addAll(page.messages)
        olderCursor = page.nextBefore
    }

    fun loadOlder() = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        val page = session?.messages(chat.conversation.id, olderCursor) ?: return@launchBusy
        messages.addAll(0, page.messages)
        olderCursor = page.nextBefore
    }

    /** Leaving a chat drops its decrypted messages. */
    fun openAdmin() {
        error = null
        screen = Screen.Admin
    }

    fun closeAdmin() {
        screen = Screen.Conversations
    }

    fun closeChat() {
        clearMedia()
        messages.clear()
        olderCursor = null
        screen = Screen.Conversations
    }

    fun send(text: String) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.sendText(chat.conversation.id, text)
        reloadChat(chat.conversation.id)
    }

    private fun clearMedia() {
        previews.clear()
        previewsRequested.clear()
        viewer = null
    }

    /** Fetches and decrypts an image preview once (shown inline). */
    fun loadPreview(message: FfiMessage) {
        if (message.media?.hasPreview != true || !previewsRequested.add(message.id)) return
        val current = session ?: return
        viewModelScope.launch {
            val bytes = runCatching { current.mediaPreview(message.id) }.getOrNull() ?: return@launch
            val bitmap = withContext(Dispatchers.Default) { decodeScaled(bytes, PREVIEW_DISPLAY_PX) }
            if (bitmap != null && messages.any { it.id == message.id }) previews[message.id] = bitmap.asImageBitmap()
        }
    }

    /** FR-011: the original is only downloaded on explicit action. */
    fun openImage(message: FfiMessage) = launchBusy {
        val bytes = session?.mediaOriginal(message.id) ?: return@launchBusy
        val bitmap = withContext(Dispatchers.Default) { decodeScaled(bytes, VIEWER_MAX_PX) }
        if (bitmap == null) error = "This image cannot be displayed." else viewer = bitmap.asImageBitmap()
    }

    /** Writes the decrypted original to a document the user picked (after the FR-012 warning). */
    fun saveMedia(message: FfiMessage, target: Uri) = launchBusy {
        val bytes = session?.mediaOriginal(message.id) ?: return@launchBusy
        withContext(Dispatchers.IO) {
            getApplication<Application>().contentResolver.openOutputStream(target)?.use { it.write(bytes) }
                ?: throw IOException("Cannot write to the selected file.")
        }
        bytes.fill(0)
    }

    /** Encrypts the picked file on this device (plus a small JPEG preview for images) and sends it. */
    fun sendMedia(source: Uri, caption: String?) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        val resolver = getApplication<Application>().contentResolver
        var name = "file"
        var size = -1L
        resolver.query(source, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                c.getString(0)?.let { name = it }
                if (!c.isNull(1)) size = c.getLong(1)
            }
        }
        if (size > MAX_MEDIA_BYTES) {
            error = "Files can be at most ${MAX_MEDIA_BYTES / (1024 * 1024)} MB."
            return@launchBusy
        }
        val mime = resolver.getType(source) ?: "application/octet-stream"
        val data = withContext(Dispatchers.IO) {
            resolver.openInputStream(source)?.use { it.readBytes() } ?: throw IOException("Cannot read the selected file.")
        }
        if (data.size > MAX_MEDIA_BYTES) {
            error = "Files can be at most ${MAX_MEDIA_BYTES / (1024 * 1024)} MB."
            return@launchBusy
        }
        val preview = if (mime.startsWith("image/")) withContext(Dispatchers.Default) { jpegPreview(data) } else null
        session?.sendMedia(chat.conversation.id, name, mime, data, preview, caption)
        data.fill(0)
        reloadChat(chat.conversation.id)
    }

    fun deleteMessages(ids: List<String>) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.deleteMessages(chat.conversation.id, ids)
        reloadChat(chat.conversation.id)
    }

    fun clearChat() = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.clearChat(chat.conversation.id)
        reloadChat(chat.conversation.id)
    }

    fun deleteAllMessages() = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.deleteAllMessages(chat.conversation.id)
        reloadChat(chat.conversation.id)
    }

    fun deleteForEveryone(message: FfiMessage) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.deleteForAll(message.id)
        reloadChat(chat.conversation.id)
    }

    fun setRetention(days: Int) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.setRetention(chat.conversation.id, days.toUShort())
        refreshConversations()
        reloadChat(chat.conversation.id)
    }

    fun newChat(usernames: List<String>, group: Boolean) = launchBusy {
        val current = session ?: return@launchBusy
        val id = current.createChat(usernames, group)
        refreshConversations()
        conversations.firstOrNull { it.id == id }?.let { openChat(it) }
    }

    fun addMember(username: String) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.addMember(chat.conversation.id, username)
        refreshConversations()
        reloadChat(chat.conversation.id)
    }

    fun leave() = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.leave(chat.conversation.id)
        closeChat()
        refreshConversations()
    }

    /** Drops keys and all decrypted content (also when the app goes to the background). */
    fun lock() {
        poller?.cancel()
        clearMedia()
        messages.clear()
        conversations.clear()
        unread.clear()
        olderCursor = null
        val current = session
        if (current != null && screen != Screen.Setup) {
            screen = Screen.Unlock
            viewModelScope.launch { current.lock() }
        }
    }

    companion object {
        const val MAX_MEDIA_BYTES = 64L * 1024 * 1024
        private const val PICKER_GRACE_MS = 5 * 60 * 1000L
        private const val PREVIEW_SEND_PX = 320
        private const val PREVIEW_DISPLAY_PX = 640
        private const val VIEWER_MAX_PX = 2048

        fun defaultDeviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()

        /** Decodes an image with its longer side at most [maxSide] pixels. */
        fun decodeScaled(bytes: ByteArray, maxSide: Int): Bitmap? {
            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
            if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
            var sample = 1
            while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= maxSide) sample *= 2
            val bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.size, BitmapFactory.Options().apply { inSampleSize = sample })
                ?: return null
            val scale = maxSide.toFloat() / maxOf(bitmap.width, bitmap.height)
            if (scale >= 1f) return bitmap
            return Bitmap.createScaledBitmap(
                bitmap, (bitmap.width * scale).toInt().coerceAtLeast(1), (bitmap.height * scale).toInt().coerceAtLeast(1), true,
            )
        }

        fun jpegPreview(bytes: ByteArray): ByteArray? {
            val bitmap = decodeScaled(bytes, PREVIEW_SEND_PX) ?: return null
            return ByteArrayOutputStream().use { out ->
                bitmap.compress(Bitmap.CompressFormat.JPEG, 80, out)
                out.toByteArray()
            }
        }
    }
}
