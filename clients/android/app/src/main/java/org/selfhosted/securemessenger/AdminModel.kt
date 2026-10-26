package org.selfhosted.securemessenger

import android.app.Application
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import uniffi.ssm_ffi.FfiAdminAccount
import uniffi.ssm_ffi.FfiAdminDevice
import uniffi.ssm_ffi.FfiAdminJob
import uniffi.ssm_ffi.FfiAdminOverview
import uniffi.ssm_ffi.FfiAuditEntry
import uniffi.ssm_ffi.FfiContentSummary
import uniffi.ssm_ffi.FfiException
import uniffi.ssm_ffi.FfiInvite
import uniffi.ssm_ffi.SsmAdmin
import uniffi.ssm_ffi.SsmSession

sealed interface AdminPhase {
    /** Checking whether an admin key exists. */
    data object Loading : AdminPhase
    /** No admin key on this device yet: choose an admin pattern. */
    data object Setup : AdminPhase
    /** Enter the admin pattern. */
    data object Login : AdminPhase
    /** The key exists but the server does not know it yet. */
    data class Unregistered(val publicKey: String) : AdminPhase
    data object Ready : AdminPhase
}

/**
 * Administration (FR-016 – FR-019). The admin key has its own pattern and is
 * bound to the Keystore; the session ends when the app locks or the admin
 * area is closed. Every action is authorised by the server.
 */
class AdminModel(application: Application) : AndroidViewModel(application) {
    private val session: SsmSession? get() = Sessions.get(getApplication())
    private var admin: SsmAdmin? = null

    var phase by mutableStateOf<AdminPhase>(AdminPhase.Loading)
        private set
    var busy by mutableStateOf(false)
        private set
    var error by mutableStateOf<String?>(null)
    /** Short confirmation shown after an action. */
    var info by mutableStateOf<String?>(null)
    /** A freshly created invite code, shown in a dialog. */
    var invite by mutableStateOf<Pair<String, FfiInvite>?>(null)

    var overview by mutableStateOf<FfiAdminOverview?>(null)
        private set
    val devices = mutableStateListOf<FfiAdminDevice>()
    val accounts = mutableStateListOf<FfiAdminAccount>()
    val jobs = mutableStateListOf<FfiAdminJob>()
    val audit = mutableStateListOf<FfiAuditEntry>()

    private fun hardwareSecret(): ByteArray = HardwareSecret.get(getApplication())

    private fun launchBusy(block: suspend () -> Unit) {
        viewModelScope.launch {
            busy = true
            error = null
            try {
                block()
            } catch (e: FfiException) {
                error = e.message ?: e.toString()
            } finally {
                busy = false
            }
        }
    }

    fun start() = launchBusy {
        if (admin != null) {
            phase = AdminPhase.Ready
            return@launchBusy
        }
        val current = session ?: return@launchBusy
        phase = if (current.adminKeyExists()) AdminPhase.Login else AdminPhase.Setup
    }

    /** Runs [block] with the Keystore-bound secret and wipes it afterwards. */
    private suspend fun <T> withSecret(block: suspend (ByteArray) -> T): T {
        val secret = hardwareSecret()
        try {
            return block(secret)
        } finally {
            secret.fill(0)
        }
    }

    private fun bytes(dots: List<Int>) = dots.map { it.toByte() }.toByteArray()

    fun createKey(dots: List<Int>) = launchBusy {
        val current = session ?: return@launchBusy
        val key = withSecret { current.createAdminKey(bytes(dots), it) }
        phase = AdminPhase.Unregistered(key)
    }

    fun login(dots: List<Int>) = launchBusy {
        val current = session ?: return@launchBusy
        val result = withSecret { current.adminLogin(bytes(dots), it) }
        val logged = result.admin
        if (logged != null) {
            admin = logged
            phase = AdminPhase.Ready
            reloadAll()
        } else {
            phase = AdminPhase.Unregistered(result.unregisteredPublicKey.orEmpty())
        }
    }

    /** After registering the key elsewhere: enter the admin pattern again. */
    fun backToLogin() {
        error = null
        phase = AdminPhase.Login
    }

    fun removeKey() = launchBusy {
        session?.removeAdminKey()
        phase = AdminPhase.Setup
    }

    private suspend fun reloadAll() {
        val a = admin ?: return
        overview = a.overview()
        devices.replace(a.devices())
        accounts.replace(a.accounts())
        jobs.replace(a.jobs())
        audit.replace(a.audit())
    }

    private fun <T> MutableList<T>.replace(items: List<T>) {
        clear()
        addAll(items)
    }

    fun refresh() = launchBusy { reloadAll() }

    /** Runs an admin action, shows its result and reloads the lists. */
    private fun act(done: String? = null, block: suspend (SsmAdmin) -> String?) = launchBusy {
        val a = admin ?: return@launchBusy
        val message = block(a)
        info = message ?: done
        reloadAll()
    }

    fun deviceAction(device: FfiAdminDevice, action: String) =
        act("${device.name} (${device.username}): ${action}d") { it.deviceAction(device.id, action); null }

    fun createAccount(username: String) = launchBusy {
        val a = admin ?: return@launchBusy
        val created = a.createAccount(username)
        invite = username to created
        reloadAll()
    }

    fun newInvite(account: FfiAdminAccount) = launchBusy {
        val a = admin ?: return@launchBusy
        invite = account.username to a.newInvite(account.id)
    }

    fun setLocked(account: FfiAdminAccount, locked: Boolean) = act { it.setAccountLocked(account.id, locked) }

    fun setAdmin(account: FfiAdminAccount, makeAdmin: Boolean) = act { it.setAdminRole(account.id, makeAdmin) }

    fun addAdminKey(account: FfiAdminAccount, publicKey: String) = act { it.addAdminKey(account.id, publicKey) }

    suspend fun contentSummary(account: FfiAdminAccount): FfiContentSummary? =
        try {
            admin?.contentSummary(account.id)
        } catch (e: FfiException) {
            error = e.message
            null
        }

    fun deleteAllContent(account: FfiAdminAccount) =
        act { val job = it.deleteAllContent(account.id); "Deleting all messages of ${account.username}: ${job.status}" }

    fun deleteAccount(account: FfiAdminAccount) = act { it.deleteAccount(account.id) }

    /** Ends the admin session; the key is opened again with the pattern next time. */
    fun clear() {
        admin = null
        overview = null
        devices.clear()
        accounts.clear()
        jobs.clear()
        audit.clear()
        invite = null
        info = null
        error = null
        phase = AdminPhase.Loading
    }

    override fun onCleared() {
        clear()
    }
}
