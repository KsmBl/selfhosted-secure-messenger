package org.selfhosted.securemessenger

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.PersistableBundle
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryScrollableTabRow
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import uniffi.ssm_ffi.FfiAdminAccount
import uniffi.ssm_ffi.FfiAdminDevice
import uniffi.ssm_ffi.FfiAdminJob
import uniffi.ssm_ffi.FfiAuditEntry
import uniffi.ssm_ffi.FfiContentSummary

/** Copies to the clipboard; marked sensitive so Android hides the preview (API 33+). */
private fun copy(context: Context, label: String, text: String, sensitive: Boolean) {
    val clip = ClipData.newPlainText(label, text)
    if (sensitive && Build.VERSION.SDK_INT >= 33) {
        clip.description.extras = PersistableBundle().apply { putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true) }
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
}

/** A pending confirmation: title, text, button label, whether destructive, action. */
private data class Confirm(
    val title: String,
    val text: String,
    val button: String,
    val destructive: Boolean,
    val action: () -> Unit,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AdminScreen(admin: AdminModel, onClose: () -> Unit) {
    LaunchedEffect(Unit) { admin.start() }
    when (val phase = admin.phase) {
        AdminPhase.Loading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        AdminPhase.Setup -> AdminKeySetup(admin, onClose)
        AdminPhase.Login -> AdminLogin(admin, onClose)
        is AdminPhase.Unregistered -> AdminUnregistered(admin, phase.publicKey, onClose)
        AdminPhase.Ready -> AdminPanel(admin, onClose)
    }
}

// ------------------------------------------------------------------ key setup / login

@Composable
private fun CloseRow(onClose: () -> Unit, content: @Composable ColumnScope.() -> Unit) {
    Box(Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize(), content = content)
        IconButton(onClick = onClose, modifier = Modifier.padding(top = 40.dp, start = 8.dp)) { Icon(AppIcons.Back, "Back") }
    }
}

@Composable
private fun AdminKeySetup(admin: AdminModel, onClose: () -> Unit) {
    val presses = remember { mutableStateListOf<Int>() }
    var first by remember { mutableStateOf<List<Int>?>(null) }
    CloseRow(onClose) {
        FormScreen(
            AppIcons.Key,
            if (first == null) "Set up administration" else "Repeat the admin pattern",
            if (first == null) {
                "Choose a separate admin pattern. It protects this device's admin key, which is bound to the phone's secure hardware."
            } else {
                "Enter the same admin pattern once more."
            },
        ) {
            StepIndicator(if (first == null) 0 else 1)
            Spacer(Modifier.height(20.dp))
            PatternPad(presses, enabled = !admin.busy)
            ErrorBanner(admin.error, { admin.error = null })
            if (admin.busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(top = 8.dp))
                Text("Creating the admin key…", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 6.dp))
            }
            Spacer(Modifier.height(16.dp))
            Button(
                enabled = !admin.busy && presses.size >= MIN_PRESSES,
                onClick = {
                    val entered = presses.toList()
                    presses.clear()
                    when {
                        first == null -> { first = entered; admin.error = null }
                        first != entered -> { first = null; admin.error = "The patterns did not match. Please choose again." }
                        else -> admin.createKey(entered)
                    }
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text(if (first == null) "Next" else "Create admin key") }
        }
    }
}

@Composable
private fun AdminLogin(admin: AdminModel, onClose: () -> Unit) {
    val presses = remember { mutableStateListOf<Int>() }
    var confirmRemove by remember { mutableStateOf(false) }
    CloseRow(onClose) {
        FormScreen(AppIcons.Shield, "Administration", "Enter your admin pattern") {
            PatternPad(presses, enabled = !admin.busy)
            ErrorBanner(admin.error, { admin.error = null })
            Spacer(Modifier.height(16.dp))
            Button(
                enabled = !admin.busy && presses.isNotEmpty(),
                onClick = { val entered = presses.toList(); presses.clear(); admin.login(entered) },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) {
                if (admin.busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                else Text("Sign in")
            }
            TextButton(onClick = { confirmRemove = true }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
                Text("Forgot the admin pattern?")
            }
        }
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            icon = { Icon(AppIcons.Key, null) },
            title = { Text("Set up a new admin key?") },
            text = {
                Text(
                    "The admin key on this phone is deleted. Afterwards you choose a new admin pattern; the new key has to " +
                        "be registered again by the operator (sudo ssm-tui → Accounts → k) or another admin.",
                )
            },
            confirmButton = {
                TextButton(onClick = { confirmRemove = false; admin.removeKey() }) {
                    Text("Delete key", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { confirmRemove = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun AdminUnregistered(admin: AdminModel, publicKey: String, onClose: () -> Unit) {
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }
    CloseRow(onClose) {
        FormScreen(
            AppIcons.Key,
            "Register your admin key",
            "The server does not know this admin key yet. Give the public key below to the operator or another admin.",
        ) {
            Card(
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Column(Modifier.padding(16.dp)) {
                    Text("Public admin key", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                    Spacer(Modifier.height(8.dp))
                    Text(publicKey, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyLarge)
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = { copy(context, "Admin public key", publicKey, false); copied = true }) {
                        Icon(if (copied) AppIcons.Check else AppIcons.Copy, null, Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(if (copied) "Copied" else "Copy")
                    }
                }
            }
            Spacer(Modifier.height(16.dp))
            StepText("1", "On the server: sudo ssm-tui → Accounts → select your account → a (admin role) and k (paste the key).")
            StepText("2", "Or another admin: Administration → Accounts → your account → Register admin key.")
            StepText("3", "Then sign in with your admin pattern.")
            Spacer(Modifier.height(16.dp))
            Button(onClick = { admin.backToLogin() }, modifier = Modifier.fillMaxWidth().height(52.dp)) { Text("Sign in") }
        }
    }
}

@Composable
private fun StepText(number: String, text: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 6.dp), verticalAlignment = Alignment.Top) {
        Box(
            Modifier.size(24.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
            contentAlignment = Alignment.Center,
        ) { Text(number, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onPrimaryContainer) }
        Spacer(Modifier.width(12.dp))
        Text(text, style = MaterialTheme.typography.bodyMedium)
    }
}

// ------------------------------------------------------------------ panel

private enum class AdminTab(val title: String, val icon: ImageVector) {
    Overview("Overview", AppIcons.Shield),
    Devices("Devices", AppIcons.Phone),
    Accounts("Accounts", AppIcons.Group),
    Jobs("Delete jobs", AppIcons.Delete),
    Audit("Audit log", AppIcons.List),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AdminPanel(admin: AdminModel, onClose: () -> Unit) {
    var tab by remember { mutableStateOf(AdminTab.Overview) }
    var confirm by remember { mutableStateOf<Confirm?>(null) }
    var newAccount by remember { mutableStateOf(false) }
    var keyFor by remember { mutableStateOf<FfiAdminAccount?>(null) }
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(admin.info) {
        admin.info?.let { snackbar.showSnackbar(it); admin.info = null }
    }

    Scaffold(
        topBar = {
            Column {
                TopAppBar(
                    navigationIcon = { IconButton(onClick = onClose) { Icon(AppIcons.Back, "Close administration") } },
                    title = { Text("Administration", fontWeight = FontWeight.SemiBold) },
                    actions = {
                        IconButton(onClick = { admin.refresh() }, enabled = !admin.busy) { Icon(AppIcons.Refresh, "Refresh") }
                    },
                )
                PrimaryScrollableTabRow(selectedTabIndex = tab.ordinal, edgePadding = 8.dp) {
                    AdminTab.entries.forEach { t ->
                        val badge = if (t == AdminTab.Devices) admin.overview?.devicesPending ?: 0 else 0
                        Tab(
                            selected = tab == t,
                            onClick = { tab = t },
                            text = { Text(if (badge > 0) "${t.title} ($badge)" else t.title) },
                            icon = { Icon(t.icon, null, Modifier.size(20.dp)) },
                        )
                    }
                }
                if (admin.busy) LinearProgressIndicator(Modifier.fillMaxWidth()) else Spacer(Modifier.height(4.dp))
            }
        },
        snackbarHost = { SnackbarHost(snackbar) },
        floatingActionButton = {
            if (tab == AdminTab.Accounts) {
                ExtendedFloatingActionButton(
                    onClick = { newAccount = true },
                    icon = { Icon(AppIcons.PersonAdd, null) },
                    text = { Text("New account") },
                )
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            ErrorBanner(admin.error, { admin.error = null }, Modifier.padding(horizontal = 16.dp))
            when (tab) {
                AdminTab.Overview -> OverviewTab(admin) { tab = it }
                AdminTab.Devices -> DevicesTab(admin) { confirm = it }
                AdminTab.Accounts -> AccountsTab(admin, onConfirm = { confirm = it }, onRegisterKey = { keyFor = it })
                AdminTab.Jobs -> JobsTab(admin.jobs)
                AdminTab.Audit -> AuditTab(admin.audit, admin.overview?.auditBrokenAt)
            }
        }
    }

    confirm?.let { c ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            icon = { Icon(if (c.destructive) AppIcons.Warning else AppIcons.Shield, null) },
            title = { Text(c.title) },
            text = { Text(c.text) },
            confirmButton = {
                Button(
                    onClick = { confirm = null; c.action() },
                    colors = if (c.destructive) {
                        ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError)
                    } else {
                        ButtonDefaults.buttonColors()
                    },
                ) { Text(c.button) }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Cancel") } },
        )
    }
    if (newAccount) {
        TextInputDialog(AppIcons.PersonAdd, "New account", "Username (3–32 characters: a–z, 0–9, . _ -)", "Create",
            onDismiss = { newAccount = false }) { name -> newAccount = false; admin.createAccount(name) }
    }
    keyFor?.let { account ->
        TextInputDialog(AppIcons.Key, "Register admin key", "Public admin key of ${account.username}", "Register",
            onDismiss = { keyFor = null }) { key -> keyFor = null; admin.addAdminKey(account, key) }
    }
    admin.invite?.let { (username, invite) -> InviteDialog(username, invite.code, invite.expiresAt) { admin.invite = null } }
}

@Composable
private fun TextInputDialog(
    icon: ImageVector,
    title: String,
    label: String,
    button: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(icon, null) },
        title = { Text(title) },
        text = {
            OutlinedTextField(value, { value = it }, label = { Text(label) }, singleLine = true, modifier = Modifier.fillMaxWidth())
        },
        confirmButton = { Button(enabled = value.isNotBlank(), onClick = { onConfirm(value.trim()) }) { Text(button) } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun InviteDialog(username: String, code: String, expiresAt: String, onDismiss: () -> Unit) {
    val context = LocalContext.current
    var copied by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(AppIcons.PersonAdd, null) },
        title = { Text("Invitation for $username") },
        text = {
            Column {
                Text("Give this one-time code to $username. It registers their first device, which you then approve.")
                Spacer(Modifier.height(16.dp))
                Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceContainerHighest) {
                    Text(
                        code,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.titleMedium,
                        modifier = Modifier.fillMaxWidth().padding(14.dp),
                    )
                }
                Spacer(Modifier.height(8.dp))
                Text("Valid until ${shortDateTime(expiresAt)}", style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Done") } },
        dismissButton = {
            TextButton(onClick = { copy(context, "Invitation code", code, true); copied = true }) {
                Text(if (copied) "Copied" else "Copy code")
            }
        },
    )
}

private fun shortDateTime(rfc3339: String): String =
    runCatching {
        java.time.OffsetDateTime.parse(rfc3339).atZoneSameInstant(java.time.ZoneId.systemDefault())
            .format(java.time.format.DateTimeFormatter.ofPattern("d MMM yyyy, HH:mm"))
    }.getOrDefault(rfc3339)

// ------------------------------------------------------------------ overview

@Composable
private fun OverviewTab(admin: AdminModel, onOpen: (AdminTab) -> Unit) {
    val o = admin.overview
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        if (o == null) return@LazyColumn
        if (o.devicesPending > 0) {
            item {
                Card(
                    onClick = { onOpen(AdminTab.Devices) },
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                        Icon(AppIcons.Phone, null)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                plural(o.devicesPending, "device") + " waiting for approval",
                                fontWeight = FontWeight.SemiBold,
                            )
                            Text("Compare the fingerprint with the person before approving.", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
        item {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatCard("Accounts", o.accounts, plural(o.admins, "admin"), AppIcons.Group, Modifier.weight(1f)) { onOpen(AdminTab.Accounts) }
                    StatCard("Active devices", o.devicesActive, "${o.devicesDisabled} disabled", AppIcons.Phone, Modifier.weight(1f)) { onOpen(AdminTab.Devices) }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    StatCard("Conversations", o.conversations, plural(o.messages, "message"), AppIcons.Chat, Modifier.weight(1f), null)
                    StatCard("Running delete jobs", o.jobsRunning, "${o.jobsBackupPending} awaiting backup purge", AppIcons.Delete, Modifier.weight(1f)) { onOpen(AdminTab.Jobs) }
                }
            }
        }
        item {
            val intact = o.auditBrokenAt == null
            Card(
                onClick = { onOpen(AdminTab.Audit) },
                colors = CardDefaults.cardColors(
                    containerColor = if (intact) MaterialTheme.colorScheme.surfaceContainerHigh else MaterialTheme.colorScheme.errorContainer,
                ),
                modifier = Modifier.fillMaxWidth(),
            ) {
                Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                    Icon(if (intact) AppIcons.Shield else AppIcons.Warning, null)
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(if (intact) "Audit log intact" else "Audit log damaged at entry ${o.auditBrokenAt}", fontWeight = FontWeight.SemiBold)
                        Text("${o.auditEntries} entries, hash chain verified", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
        }
    }
}

private fun plural(n: Long, word: String) = "$n $word${if (n == 1L) "" else "s"}"

@Composable
private fun StatCard(title: String, value: Long, detail: String, icon: ImageVector, modifier: Modifier, onClick: (() -> Unit)?) {
    Card(
        onClick = { onClick?.invoke() },
        enabled = onClick != null,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            disabledContainerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
            disabledContentColor = MaterialTheme.colorScheme.onSurface,
        ),
        modifier = modifier.height(150.dp),
    ) {
        Column(Modifier.padding(16.dp)) {
            Icon(icon, null, Modifier.size(22.dp), tint = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(10.dp))
            Text("$value", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.SemiBold)
            Text(title, style = MaterialTheme.typography.titleSmall)
            Text(detail, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ------------------------------------------------------------------ devices

@Composable
private fun StatusChip(status: String) {
    val (bg, fg) = when (status) {
        "pending" -> MaterialTheme.colorScheme.tertiaryContainer to MaterialTheme.colorScheme.onTertiaryContainer
        "active", "backup_purge_done" -> MaterialTheme.colorScheme.primaryContainer to MaterialTheme.colorScheme.onPrimaryContainer
        "disabled", "failed" -> MaterialTheme.colorScheme.errorContainer to MaterialTheme.colorScheme.onErrorContainer
        else -> MaterialTheme.colorScheme.surfaceContainerHighest to MaterialTheme.colorScheme.onSurfaceVariant
    }
    Surface(shape = CircleShape, color = bg, contentColor = fg) {
        Text(status.replace('_', ' '), style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 10.dp, vertical = 3.dp))
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DevicesTab(admin: AdminModel, onConfirm: (Confirm) -> Unit) {
    var filter by remember { mutableStateOf("pending") }
    val shown = admin.devices.filter { filter == "all" || it.status == filter }
    LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        item {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                for ((value, label) in listOf("pending" to "Pending", "active" to "Active", "disabled" to "Disabled", "all" to "All")) {
                    val count = if (value == "all") admin.devices.size else admin.devices.count { it.status == value }
                    FilterChip(filter == value, { filter = value }, label = { Text("$label $count") })
                }
            }
        }
        if (shown.isEmpty()) {
            item { EmptyHint(AppIcons.Phone, if (filter == "pending") "No devices waiting for approval" else "No devices") }
        }
        items(shown, key = { it.id }) { device -> DeviceCard(device, admin, onConfirm) }
    }
}

@Composable
private fun DeviceCard(device: FfiAdminDevice, admin: AdminModel, onConfirm: (Confirm) -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(device.username, group = false, size = 40)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(device.name, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text("${device.username} · since ${shortDateTime(device.createdAt)}", style = MaterialTheme.typography.bodySmall)
                }
                StatusChip(device.status)
            }
            Spacer(Modifier.height(12.dp))
            Text("Fingerprint", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
            Text(device.fingerprint, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodyMedium)
            Spacer(Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                val who = "${device.name} (${device.username})"
                when (device.status) {
                    "pending" -> {
                        OutlinedButton(onClick = {
                            onConfirm(Confirm("Reject $who?", "The device is deleted and has to register again.", "Reject", true) {
                                admin.deviceAction(device, "reject")
                            })
                        }) { Text("Reject") }
                        Button(onClick = {
                            onConfirm(Confirm("Approve $who?", "Only approve if the fingerprint matches what the person sees on their device:\n\n${device.fingerprint}", "Approve", false) {
                                admin.deviceAction(device, "approve")
                            })
                        }) { Text("Approve") }
                    }
                    "active" -> {
                        OutlinedButton(onClick = {
                            onConfirm(Confirm("Disable $who?", "The device is signed out at once and cannot be used until you enable it again.", "Disable", false) {
                                admin.deviceAction(device, "disable")
                            })
                        }) { Text("Disable") }
                        RevokeButton(who, device, admin, onConfirm)
                    }
                    "disabled" -> {
                        OutlinedButton(onClick = { admin.deviceAction(device, "enable") }) { Text("Enable") }
                        RevokeButton(who, device, admin, onConfirm)
                    }
                }
            }
        }
    }
}

@Composable
private fun RevokeButton(who: String, device: FfiAdminDevice, admin: AdminModel, onConfirm: (Confirm) -> Unit) {
    Button(
        onClick = {
            onConfirm(Confirm("Revoke $who?", "The device is deleted for good, with its keys and sessions. Messages it sent stay readable for the others.", "Revoke", true) {
                admin.deviceAction(device, "revoke")
            })
        },
        colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError),
    ) { Text("Revoke") }
}

@Composable
private fun EmptyHint(icon: ImageVector, text: String) {
    Column(Modifier.fillMaxWidth().padding(top = 64.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        IconBadge(icon, size = 72)
        Spacer(Modifier.height(16.dp))
        Text(text, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ------------------------------------------------------------------ accounts

@Composable
private fun AccountsTab(admin: AdminModel, onConfirm: (Confirm) -> Unit, onRegisterKey: (FfiAdminAccount) -> Unit) {
    val scope = rememberCoroutineScope()
    LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 96.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        items(admin.accounts, key = { it.id }) { account ->
            AccountCard(
                account,
                onInvite = { admin.newInvite(account) },
                onLock = { lock ->
                    onConfirm(Confirm(
                        if (lock) "Lock ${account.username}?" else "Unlock ${account.username}?",
                        if (lock) "All devices of the account are signed out at once. Messages stay." else "The account's devices can sign in again.",
                        if (lock) "Lock" else "Unlock", lock,
                    ) { admin.setLocked(account, lock) })
                },
                onAdmin = { makeAdmin ->
                    onConfirm(Confirm(
                        if (makeAdmin) "Make ${account.username} an admin?" else "Remove admin rights of ${account.username}?",
                        if (makeAdmin) "They also need an admin key (Register admin key) to use the administration." else "Their admin keys are revoked.",
                        if (makeAdmin) "Make admin" else "Remove", !makeAdmin,
                    ) { admin.setAdmin(account, makeAdmin) })
                },
                onRegisterKey = { onRegisterKey(account) },
                onDeleteContent = {
                    scope.launch {
                        val summary: FfiContentSummary = admin.contentSummary(account) ?: return@launch
                        onConfirm(Confirm(
                            "Delete everything ${account.username} sent?",
                            "${summary.messages} messages in ${summary.conversations} conversations are deleted for everyone. " +
                                "Messages of other people stay. This cannot be undone.",
                            "Delete ${summary.messages} messages", true,
                        ) { admin.deleteAllContent(account) })
                    }
                },
                onDeleteAccount = {
                    onConfirm(Confirm(
                        "Delete the account ${account.username}?",
                        "All their messages are deleted for everyone, they leave all conversations, and their devices, keys and invitations are removed. " +
                            "The username becomes free again. This cannot be undone.",
                        "Delete account", true,
                    ) { admin.deleteAccount(account) })
                },
            )
        }
    }
}

@Composable
private fun AccountCard(
    account: FfiAdminAccount,
    onInvite: () -> Unit,
    onLock: (Boolean) -> Unit,
    onAdmin: (Boolean) -> Unit,
    onRegisterKey: () -> Unit,
    onDeleteContent: () -> Unit,
    onDeleteAccount: () -> Unit,
) {
    var menu by remember { mutableStateOf(false) }
    val locked = account.status != "active"
    val isAdmin = account.role == "admin"
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh), modifier = Modifier.fillMaxWidth()) {
        Row(Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp), verticalAlignment = Alignment.CenterVertically) {
            Avatar(account.username, group = false, size = 44)
            Spacer(Modifier.width(12.dp))
            Column(Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(account.username, fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    if (isAdmin) {
                        Spacer(Modifier.width(8.dp))
                        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primary, contentColor = MaterialTheme.colorScheme.onPrimary) {
                            Text("admin", style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp))
                        }
                    }
                    if (locked) {
                        Spacer(Modifier.width(6.dp))
                        StatusChip("locked")
                    }
                }
                Text(
                    plural(account.activeDevices, "device") + " · " + plural(account.messages, "message"),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Box {
                IconButton(onClick = { menu = true }) { Icon(AppIcons.More, "Actions for ${account.username}") }
                DropdownMenu(menu, onDismissRequest = { menu = false }) {
                    DropdownMenuItem(text = { Text("New invitation code") }, leadingIcon = { Icon(AppIcons.PersonAdd, null) }, onClick = { menu = false; onInvite() })
                    DropdownMenuItem(
                        text = { Text(if (locked) "Unlock account" else "Lock account") },
                        leadingIcon = { Icon(AppIcons.Lock, null) },
                        onClick = { menu = false; onLock(!locked) },
                    )
                    DropdownMenuItem(
                        text = { Text(if (isAdmin) "Remove admin rights" else "Make admin") },
                        leadingIcon = { Icon(AppIcons.Shield, null) },
                        onClick = { menu = false; onAdmin(!isAdmin) },
                    )
                    if (isAdmin) {
                        DropdownMenuItem(text = { Text("Register admin key") }, leadingIcon = { Icon(AppIcons.Key, null) }, onClick = { menu = false; onRegisterKey() })
                    }
                    HorizontalDivider()
                    val red = MaterialTheme.colorScheme.error
                    DropdownMenuItem(
                        text = { Text("Delete all their messages", color = red) },
                        leadingIcon = { Icon(AppIcons.Delete, null, tint = red) },
                        onClick = { menu = false; onDeleteContent() },
                    )
                    DropdownMenuItem(
                        text = { Text("Delete account", color = red) },
                        leadingIcon = { Icon(AppIcons.Close, null, tint = red) },
                        onClick = { menu = false; onDeleteAccount() },
                    )
                }
            }
        }
    }
}

// ------------------------------------------------------------------ jobs / audit

@Composable
private fun JobsTab(jobs: List<FfiAdminJob>) {
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        if (jobs.isEmpty()) item { EmptyHint(AppIcons.Delete, "No delete jobs yet") }
        items(jobs, key = { it.id }) { job ->
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh), modifier = Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(job.scope.replaceFirstChar { it.uppercase() }, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
                        StatusChip(job.status)
                    }
                    Spacer(Modifier.height(4.dp))
                    Text("${job.affectedMessages} messages · ${shortDateTime(job.createdAt)}", style = MaterialTheme.typography.bodySmall)
                    job.backupPurgeDueAt?.let {
                        Text("Gone from backups after ${shortDateTime(it)}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    job.error?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error) }
                }
            }
        }
    }
}

@Composable
private fun AuditTab(entries: List<FfiAuditEntry>, brokenAt: Long?) {
    LazyColumn(contentPadding = PaddingValues(vertical = 8.dp)) {
        if (brokenAt != null) {
            item {
                Card(
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                ) { Text("The hash chain is broken at entry $brokenAt: the log was changed outside the server.", Modifier.padding(16.dp)) }
            }
        }
        items(entries, key = { it.id }) { entry ->
            val failed = !entry.result.startsWith("ok")
            Row(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 10.dp)) {
                Box(
                    Modifier.padding(top = 6.dp).size(8.dp)
                        .background(if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary, CircleShape),
                )
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Row {
                        Text(entry.action, fontWeight = FontWeight.SemiBold, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                        Text("#${entry.id}", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                    }
                    Text(entry.target, style = MaterialTheme.typography.bodySmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        "${entry.result} · ${shortDateTime(entry.createdAt)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (failed) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            HorizontalDivider(Modifier.padding(start = 36.dp))
        }
    }
}
