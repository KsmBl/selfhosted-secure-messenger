package org.selfhosted.securemessenger

import android.app.Application
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import uniffi.ssm_ffi.FfiConversation
import uniffi.ssm_ffi.FfiException
import uniffi.ssm_ffi.FfiMessage
import uniffi.ssm_ffi.FfiUpdate
import uniffi.ssm_ffi.SsmSession
import uniffi.ssm_ffi.enroll
import uniffi.ssm_ffi.openProfile
import uniffi.ssm_ffi.profileExists

sealed interface Screen {
    data object Setup : Screen
    data class Pending(val fingerprint: String) : Screen
    data object Unlock : Screen
    data object Conversations : Screen
    data class Chat(val conversation: FfiConversation) : Screen
}

/**
 * App state. Decrypted messages exist only in [messages] for the open chat
 * and are dropped when the chat is left or the app is locked (FR-013).
 */
class AppModel(application: Application) : AndroidViewModel(application) {
    private val profileDir = application.noBackupFilesDir.resolve("profile").absolutePath
    private var session: SsmSession? = null
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

    init {
        if (screen == Screen.Unlock) {
            session = openProfile(profileDir)
        }
    }

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
            session = newSession
            screen = Screen.Pending(newSession.fingerprint())
            startPolling()
        } finally {
            secret.fill(0)
        }
    }

    fun unlock(dots: List<Int>) = launchBusy {
        val current = session ?: openProfile(profileDir).also { session = it }
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
    fun closeChat() {
        messages.clear()
        olderCursor = null
        screen = Screen.Conversations
    }

    fun send(text: String) = launchBusy {
        val chat = screen as? Screen.Chat ?: return@launchBusy
        session?.sendText(chat.conversation.id, text)
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
        fun defaultDeviceName(): String = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
    }
}
