package org.selfhosted.securemessenger

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import uniffi.ssm_ffi.FfiConversation
import uniffi.ssm_ffi.FfiMediaKind
import uniffi.ssm_ffi.FfiMessage
import uniffi.ssm_ffi.FfiMessageKind

private const val MIN_PRESSES = 6

@Composable
fun App(model: AppModel) {
    // Follows the system light/dark mode; Android 12+ also uses the system
    // (wallpaper) colours, so the app looks like part of the OS.
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = colors) {
        Surface(Modifier.fillMaxSize()) {
            when (val screen = model.screen) {
                Screen.Setup -> SetupScreen(model)
                is Screen.Pending -> PendingScreen(model, screen.fingerprint)
                Screen.Unlock -> UnlockScreen(model)
                Screen.Conversations -> ConversationsScreen(model)
                is Screen.Chat -> ChatScreen(model, screen.conversation)
            }
        }
    }
}

/** 5×5 dots, any order, repeats allowed; only the count is shown (no trail). */
@Composable
fun PatternPad(presses: MutableList<Int>) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        for (row in 0 until 5) {
            Row {
                for (col in 0 until 5) {
                    Box(
                        Modifier
                            .padding(6.dp)
                            .size(48.dp)
                            .background(MaterialTheme.colorScheme.surfaceVariant, CircleShape)
                            .clickable { if (presses.size < 64) presses.add(row * 5 + col) },
                        contentAlignment = Alignment.Center,
                    ) {
                        Box(Modifier.size(10.dp).background(MaterialTheme.colorScheme.onSurfaceVariant, CircleShape))
                    }
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            if (presses.isEmpty()) "Press at least $MIN_PRESSES dots, in any order, as often as you like."
            else "${presses.size} presses",
        )
        TextButton(onClick = { presses.clear() }) { Text("Clear") }
    }
}

@Composable
private fun ErrorText(model: AppModel) {
    model.error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(vertical = 8.dp)) }
}

@Composable
private fun Centered(title: String, content: @Composable ColumnScope.() -> Unit) {
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp),
        verticalArrangement = Arrangement.Center,
    ) {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Spacer(Modifier.height(16.dp))
        content()
    }
}

@Composable
fun SetupScreen(model: AppModel) {
    var server by remember { mutableStateOf("https://") }
    var code by remember { mutableStateOf("") }
    var withInvite by remember { mutableStateOf(true) }
    var deviceName by remember { mutableStateOf(AppModel.defaultDeviceName()) }
    var step by remember { mutableStateOf(0) }
    var first by remember { mutableStateOf<List<Int>?>(null) }
    val presses = remember { mutableStateListOf<Int>() }

    Centered("Device setup") {
        if (step == 0) {
            Text("Register this device with your messenger server. An administrator has to approve it before you can chat.")
            OutlinedTextField(server, { server = it }, label = { Text("Server address") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(), keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(withInvite, { withInvite = true }); Text("I have an invitation code")
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                RadioButton(!withInvite, { withInvite = false }); Text("Add to my existing account")
            }
            OutlinedTextField(code, { code = it }, label = { Text(if (withInvite) "Invitation code" else "Username") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(deviceName, { deviceName = it }, label = { Text("Name of this device") },
                singleLine = true, modifier = Modifier.fillMaxWidth())
            ErrorText(model)
            Button(
                onClick = { if (server.length > 8 && code.isNotBlank()) { model.error = null; step = 1 } else model.error = "Please fill in all fields." },
                modifier = Modifier.align(Alignment.End),
            ) { Text("Next") }
        } else {
            Text(
                if (first == null) "Choose an unlock pattern. It protects the keys on this device and is never sent to the server."
                else "Repeat the pattern to confirm it.",
            )
            Spacer(Modifier.height(12.dp))
            PatternPad(presses)
            ErrorText(model)
            if (model.busy) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(Modifier.size(24.dp)); Spacer(Modifier.size(8.dp)); Text("Registering… (a few seconds)")
                }
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.align(Alignment.End)) {
                OutlinedButton(onClick = { presses.clear(); first = null; step = 0 }) { Text("Back") }
                Button(enabled = !model.busy, onClick = {
                    val entered = presses.toList()
                    presses.clear()
                    when {
                        entered.size < MIN_PRESSES -> model.error = "The pattern needs at least $MIN_PRESSES presses."
                        first == null -> { first = entered; model.error = null }
                        first != entered -> { first = null; model.error = "The patterns did not match. Please choose again." }
                        else -> model.register(server, code, withInvite, deviceName, entered)
                    }
                }) { Text("Next") }
            }
        }
    }
}

@Composable
fun PendingScreen(model: AppModel, fingerprint: String) {
    Centered("Waiting for approval") {
        Text("This device is registered and waits for an administrator to approve it.")
        Spacer(Modifier.height(12.dp))
        Text("Device fingerprint (tell your administrator):")
        Text(fingerprint, fontWeight = FontWeight.Bold)
        ErrorText(model)
        Spacer(Modifier.height(12.dp))
        Button(onClick = { model.refresh() }) { Text("Check now") }
    }
}

@Composable
fun UnlockScreen(model: AppModel) {
    val presses = remember { mutableStateListOf<Int>() }
    Centered("Secure Messenger is locked") {
        PatternPad(presses)
        ErrorText(model)
        Button(
            enabled = !model.busy,
            onClick = { val entered = presses.toList(); presses.clear(); model.unlock(entered) },
            modifier = Modifier.align(Alignment.End),
        ) { Text(if (model.busy) "Unlocking…" else "Unlock") }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationsScreen(model: AppModel) {
    var newChat by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(title = { Text("Chats" + (model.username?.let { " — $it" } ?: "")) }, actions = {
                TextButton(onClick = { model.refresh() }) { Text("Refresh") }
                TextButton(onClick = { model.lock() }) { Text("Lock") }
            })
        },
        floatingActionButton = { FloatingActionButton(onClick = { newChat = true }) { Text("+", style = MaterialTheme.typography.headlineMedium) } },
    ) { padding ->
        Column(Modifier.padding(padding)) {
            ErrorText(model)
            if (!model.pushAvailable) {
                Text(
                    "No notifications while the app is closed: install a UnifiedPush app such as ntfy.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            if (model.conversations.isEmpty()) {
                Text("No conversations yet. Start one with +.", Modifier.padding(16.dp))
            }
            LazyColumn {
                items(model.conversations, key = { it.id }) { conv ->
                    val unread = conv.id in model.unread
                    Column(Modifier.fillMaxWidth().clickable { model.openChat(conv) }.padding(16.dp)) {
                        Text((if (unread) "• " else "") + conv.title, fontWeight = if (unread) FontWeight.Bold else FontWeight.Normal)
                        Text("Messages are deleted after ${conv.retentionDays} days", style = MaterialTheme.typography.bodySmall)
                    }
                    HorizontalDivider()
                }
            }
        }
    }
    if (newChat) NewChatDialog(onDismiss = { newChat = false }) { names, group -> newChat = false; model.newChat(names, group) }
}

@Composable
private fun NewChatDialog(onDismiss: () -> Unit, onCreate: (List<String>, Boolean) -> Unit) {
    var names by remember { mutableStateOf("") }
    var group by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New chat") },
        text = {
            Column {
                OutlinedTextField(names, { names = it }, label = { Text(if (group) "Usernames, comma separated" else "Username") }, singleLine = true)
                Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(group, { group = it }); Text("Group") }
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val list = names.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                if (list.isNotEmpty()) onCreate(list, group || list.size > 1)
            }) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private val timeFormat = DateTimeFormatter.ofPattern("dd.MM. HH:mm")

private fun shortTime(rfc3339: String): String =
    runCatching { OffsetDateTime.parse(rfc3339).atZoneSameInstant(ZoneId.systemDefault()).format(timeFormat) }.getOrDefault("")

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun ChatScreen(model: AppModel, conversation: FfiConversation) {
    var text by remember { mutableStateOf("") }
    var toDelete by remember { mutableStateOf<FfiMessage?>(null) }
    var dialog by remember { mutableStateOf<String?>(null) }
    var confirmSave by remember { mutableStateOf<FfiMessage?>(null) }
    var saving by remember { mutableStateOf<FfiMessage?>(null) }
    val attach = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            model.sendMedia(uri, text.trim().ifEmpty { null })
            text = ""
        }
    }
    val saveTo = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val message = saving
        saving = null
        if (uri != null && message != null) model.saveMedia(message, uri)
    }
    val list = rememberLazyListState()
    LaunchedEffect(model.messages.size) { if (model.messages.isNotEmpty()) list.scrollToItem(model.messages.size) }

    Scaffold(
        modifier = Modifier.imePadding(),
        topBar = {
            TopAppBar(title = { Text(conversation.title) }, navigationIcon = {
                TextButton(onClick = { model.closeChat() }) { Text("Back") }
            }, actions = {
                TextButton(onClick = { dialog = "retention" }) { Text("${conversation.retentionDays} d") }
                if (conversation.isGroup && conversation.iAmAdmin) TextButton(onClick = { dialog = "add" }) { Text("Invite") }
                if (conversation.isGroup) TextButton(onClick = { dialog = "leave" }) { Text("Leave") }
            })
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            ErrorText(model)
            LazyColumn(Modifier.weight(1f).padding(horizontal = 8.dp), state = list) {
                item {
                    if (model.olderCursor != null) {
                        TextButton(onClick = { model.loadOlder() }, modifier = Modifier.fillMaxWidth()) { Text("Load older messages") }
                    }
                }
                items(model.messages, key = { it.id }) { message ->
                    MessageRow(
                        message,
                        preview = model.previews[message.id],
                        onNeedPreview = { model.loadPreview(message) },
                        onOpen = { model.openImage(message) },
                        onSave = { confirmSave = message },
                        onLongPress = { if (message.kind == FfiMessageKind.TEXT || message.kind == FfiMessageKind.MEDIA) toDelete = message },
                    )
                }
            }
            Row(Modifier.padding(8.dp), verticalAlignment = Alignment.CenterVertically) {
                IconButton(enabled = !model.busy, onClick = {
                    model.pickerOpenedAt = android.os.SystemClock.elapsedRealtime()
                    attach.launch(arrayOf("*/*"))
                }) { Text("📎") }
                OutlinedTextField(text, { text = it }, Modifier.weight(1f), placeholder = { Text("Write a message…") })
                Spacer(Modifier.size(8.dp))
                Button(enabled = text.isNotBlank() && !model.busy, onClick = { model.send(text.trim()); text = "" }) { Text("Send") }
            }
        }
    }

    toDelete?.let { message ->
        AlertDialog(
            onDismissRequest = { toDelete = null },
            title = { Text("Delete for everyone?") },
            text = { Text("The message is removed for all participants. Copies someone exported or photographed cannot be recalled.") },
            confirmButton = { TextButton(onClick = { toDelete = null; model.deleteForEveryone(message) }) { Text("Delete for everyone") } },
            dismissButton = { TextButton(onClick = { toDelete = null }) { Text("Cancel") } },
        )
    }
    confirmSave?.let { message ->
        AlertDialog(
            onDismissRequest = { confirmSave = null },
            title = { Text("Save ${message.media?.name ?: "file"} to this device?") },
            text = { Text("A saved copy is outside the app: deleting the message for everyone later will not remove it, and it is not encrypted on the device.") },
            confirmButton = {
                TextButton(onClick = {
                    confirmSave = null
                    saving = message
                    model.pickerOpenedAt = android.os.SystemClock.elapsedRealtime()
                    saveTo.launch(message.media?.name ?: "file")
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { confirmSave = null }) { Text("Cancel") } },
        )
    }
    model.viewer?.let { image ->
        Dialog(onDismissRequest = { model.viewer = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Box(Modifier.fillMaxSize().background(Color.Black).clickable { model.viewer = null }, contentAlignment = Alignment.Center) {
                Image(image, contentDescription = null, modifier = Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
            }
        }
    }
    when (dialog) {
        "retention" -> InputDialog("Retention period", "Days until messages are deleted (1–365). All members see the change.",
            conversation.retentionDays.toString(), KeyboardType.Number, onDismiss = { dialog = null }) { value ->
            dialog = null
            value.toIntOrNull()?.takeIf { it in 1..365 }?.let { model.setRetention(it) } ?: run { model.error = "Please enter 1–365 days." }
        }
        "add" -> InputDialog("Invite to group", "Username:", "", KeyboardType.Text, onDismiss = { dialog = null }) { value ->
            dialog = null; model.addMember(value)
        }
        "leave" -> AlertDialog(
            onDismissRequest = { dialog = null },
            title = { Text("Leave this group?") },
            text = { Text("You will no longer see its messages.") },
            confirmButton = { TextButton(onClick = { dialog = null; model.leave() }) { Text("Leave") } },
            dismissButton = { TextButton(onClick = { dialog = null }) { Text("Cancel") } },
        )
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageRow(
    message: FfiMessage,
    preview: ImageBitmap?,
    onNeedPreview: () -> Unit,
    onOpen: () -> Unit,
    onSave: () -> Unit,
    onLongPress: () -> Unit,
) {
    val isNotice = message.kind != FfiMessageKind.TEXT && message.kind != FfiMessageKind.MEDIA
    Column(
        Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalAlignment = if (isNotice) Alignment.CenterHorizontally else if (message.mine) Alignment.End else Alignment.Start,
    ) {
        if (isNotice) {
            Text("${shortTime(message.createdAt)}  ${message.text}", style = MaterialTheme.typography.bodySmall,
                fontStyle = FontStyle.Italic, color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            Column(
                Modifier
                    .widthIn(max = 300.dp)
                    .background(
                        if (message.mine) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                        RoundedCornerShape(10.dp),
                    )
                    .combinedClickable(onClick = {}, onLongClick = onLongPress)
                    .padding(10.dp),
            ) {
                if (!message.mine) Text(message.sender, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelMedium)
                val media = message.media
                if (media != null) {
                    val isImage = media.kind == FfiMediaKind.IMAGE
                    if (media.hasPreview) {
                        LaunchedEffect(message.id) { onNeedPreview() }
                        if (preview != null) {
                            Image(preview, contentDescription = media.name,
                                modifier = Modifier.widthIn(max = 280.dp).clickable(enabled = isImage, onClick = onOpen))
                        } else {
                            Box(Modifier.size(120.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
                        }
                    }
                    Text("📄 ${media.name} (${humanSize(media.size)})", style = MaterialTheme.typography.bodySmall)
                    if (message.text.isNotEmpty()) Text(message.text)
                    Row {
                        if (isImage) TextButton(onClick = onOpen) { Text("Open") }
                        TextButton(onClick = onSave) { Text("Save…") }
                    }
                } else {
                    Text(message.text)
                }
                Text(shortTime(message.createdAt), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}

private fun humanSize(bytes: ULong): String {
    val b = bytes.toDouble()
    return when {
        b < 1024 -> "$bytes bytes"
        b < 1024 * 1024 -> "%.1f KB".format(b / 1024)
        else -> "%.1f MB".format(b / (1024 * 1024))
    }
}

@Composable
private fun InputDialog(
    title: String,
    label: String,
    initial: String,
    keyboard: KeyboardType,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var value by remember { mutableStateOf(initial) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = {
            Column {
                Text(label)
                OutlinedTextField(value, { value = it }, singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = keyboard))
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(value.trim()) }) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
