package org.selfhosted.securemessenger

import android.os.SystemClock
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Badge
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilledIconButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.animation.core.Animatable
import androidx.compose.foundation.gestures.detectHorizontalDragGestures
import androidx.compose.foundation.layout.offset
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.draw.clip
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.IntOffset
import kotlin.math.roundToInt
import kotlinx.coroutines.launch
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.time.temporal.ChronoUnit
import uniffi.ssm_ffi.FfiConversation
import uniffi.ssm_ffi.FfiMediaKind
import uniffi.ssm_ffi.FfiMessage
import uniffi.ssm_ffi.FfiMessageKind

internal const val MIN_PRESSES = 6

@Composable
fun App(model: AppModel, admin: AdminModel, onAllowBackground: () -> Unit = {}) {
    AppTheme {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            when (val screen = model.screen) {
                Screen.Setup -> SetupScreen(model)
                is Screen.Pending -> PendingScreen(model, screen.fingerprint)
                Screen.Unlock -> UnlockScreen(model)
                Screen.Conversations -> ConversationsScreen(model, onAllowBackground)
                is Screen.Chat -> ChatScreen(model, screen.conversation)
                Screen.Admin -> AdminScreen(admin, onClose = { admin.clear(); model.closeAdmin() })
            }
        }
    }
}

// ------------------------------------------------------------------ shared pieces

/** Round tinted badge with an icon (screen headers, empty states). */
@Composable
internal fun IconBadge(icon: ImageVector, size: Int = 72) {
    Box(
        Modifier.size(size.dp).background(MaterialTheme.colorScheme.primaryContainer, CircleShape),
        contentAlignment = Alignment.Center,
    ) {
        Icon(icon, null, Modifier.size((size * 0.5).dp), tint = MaterialTheme.colorScheme.onPrimaryContainer)
    }
}

@Composable
internal fun Avatar(name: String, group: Boolean, size: Int = 44) {
    Box(Modifier.size(size.dp).background(colorFor(name), CircleShape), contentAlignment = Alignment.Center) {
        if (group) {
            Icon(AppIcons.Group, null, Modifier.size((size * 0.55).dp), tint = Color.White)
        } else {
            Text(
                name.firstOrNull()?.uppercase() ?: "?",
                color = Color.White,
                fontWeight = FontWeight.SemiBold,
                style = if (size >= 44) MaterialTheme.typography.titleMedium else MaterialTheme.typography.labelLarge,
            )
        }
    }
}

@Composable
private fun ErrorCard(model: AppModel, modifier: Modifier = Modifier) =
    ErrorBanner(model.error, { model.error = null }, modifier)

@Composable
internal fun ErrorBanner(error: String?, onDismiss: () -> Unit, modifier: Modifier = Modifier) {
    AnimatedVisibility(error != null, modifier) {
        Card(
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            ),
            modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        ) {
            Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(AppIcons.Warning, null, Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Text(error.orEmpty(), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.weight(1f))
                IconButton(onClick = onDismiss, modifier = Modifier.size(32.dp)) {
                    Icon(AppIcons.Close, "Dismiss", Modifier.size(18.dp))
                }
            }
        }
    }
}

/** Full-screen, centered form layout for setup, pending and unlock. */
@Composable
internal fun FormScreen(
    icon: ImageVector,
    title: String,
    subtitle: String?,
    content: @Composable ColumnScope.() -> Unit,
) {
    Column(
        Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .imePadding()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 24.dp, vertical = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        IconBadge(icon)
        Spacer(Modifier.height(20.dp))
        Text(title, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
        if (subtitle != null) {
            Spacer(Modifier.height(8.dp))
            Text(
                subtitle,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }
        Spacer(Modifier.height(24.dp))
        Column(Modifier.widthIn(max = 480.dp).fillMaxWidth(), content = content)
    }
}

// ------------------------------------------------------------------ pattern

/**
 * 5×5 dots, any order, repeats allowed (FR-003). Only the number of presses
 * is shown; a dot lights up only while it is touched (no trail).
 */
@Composable
fun PatternPad(presses: MutableList<Int>, enabled: Boolean = true) {
    Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
        Surface(
            shape = RoundedCornerShape(28.dp),
            color = MaterialTheme.colorScheme.surfaceContainerHigh,
            modifier = Modifier.widthIn(max = 360.dp).fillMaxWidth(),
        ) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                for (row in 0 until 5) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly) {
                        for (col in 0 until 5) {
                            PatternDot(enabled) { if (presses.size < 64) presses.add(row * 5 + col) }
                        }
                    }
                }
            }
        }
        Spacer(Modifier.height(16.dp))
        // Press counter: dots for the count, never which dot was pressed.
        Row(
            Modifier.height(28.dp).fillMaxWidth(),
            horizontalArrangement = Arrangement.Center,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (presses.isEmpty()) {
                Text(
                    "Press at least $MIN_PRESSES dots — any order, repeats allowed",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                val shown = presses.size.coerceAtMost(16)
                repeat(shown) {
                    Box(
                        Modifier
                            .padding(horizontal = 3.dp)
                            .size(9.dp)
                            .background(
                                if (presses.size >= MIN_PRESSES) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.outline,
                                CircleShape,
                            ),
                    )
                }
                if (presses.size > shown) {
                    Text(" +${presses.size - shown}", style = MaterialTheme.typography.labelMedium)
                }
                Spacer(Modifier.width(8.dp))
                IconButton(onClick = { presses.clear() }, modifier = Modifier.size(28.dp)) {
                    Icon(AppIcons.Backspace, "Clear", Modifier.size(18.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        }
    }
}

@Composable
private fun PatternDot(enabled: Boolean, onPress: () -> Unit) {
    val interaction = remember { MutableInteractionSource() }
    val pressed by interaction.collectIsPressedAsState()
    val ring by animateColorAsState(
        if (pressed) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceContainerHighest,
        label = "ring",
    )
    val center by animateColorAsState(
        if (pressed) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
        label = "center",
    )
    val scale by animateFloatAsState(if (pressed) 1.5f else 1f, label = "scale")
    Box(
        Modifier
            .padding(4.dp)
            .size(50.dp)
            .clip(CircleShape)
            .background(ring)
            .clickable(interactionSource = interaction, indication = null, enabled = enabled, onClick = onPress),
        contentAlignment = Alignment.Center,
    ) {
        Box(Modifier.size(10.dp).scale(scale).background(center, CircleShape))
    }
}

// ------------------------------------------------------------------ setup / pending / unlock

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SetupScreen(model: AppModel) {
    var server by remember { mutableStateOf("https://") }
    var code by remember { mutableStateOf("") }
    var withInvite by remember { mutableStateOf(true) }
    var deviceName by remember { mutableStateOf(AppModel.defaultDeviceName()) }
    var step by remember { mutableStateOf(0) }
    var first by remember { mutableStateOf<List<Int>?>(null) }
    val presses = remember { mutableStateListOf<Int>() }

    val (title, subtitle) = when {
        step == 0 -> "Welcome" to "Register this device with your messenger server. An administrator approves it before you can chat."
        first == null -> "Choose an unlock pattern" to "It protects the keys on this device and never leaves it."
        else -> "Repeat your pattern" to "Enter the same pattern once more to confirm it."
    }
    FormScreen(if (step == 0) AppIcons.Shield else AppIcons.Lock, title, subtitle) {
        StepIndicator(if (step == 0) 0 else if (first == null) 1 else 2)
        Spacer(Modifier.height(20.dp))
        if (step == 0) {
            OutlinedTextField(
                server, { server = it },
                label = { Text("Server address") },
                supportingText = { Text("e.g. https://messenger.example.org or http://192.168.1.10:8080") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
            )
            Spacer(Modifier.height(12.dp))
            SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                SegmentedButton(withInvite, { withInvite = true }, SegmentedButtonDefaults.itemShape(0, 2)) {
                    Text("Invitation code")
                }
                SegmentedButton(!withInvite, { withInvite = false }, SegmentedButtonDefaults.itemShape(1, 2)) {
                    Text("Existing account")
                }
            }
            Spacer(Modifier.height(12.dp))
            OutlinedTextField(
                code, { code = it },
                label = { Text(if (withInvite) "Invitation code" else "Username") },
                supportingText = {
                    Text(if (withInvite) "From your administrator" else "Adds this device to your account")
                },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                keyboardOptions = KeyboardOptions(
                    capitalization = if (withInvite) KeyboardCapitalization.Characters else KeyboardCapitalization.None,
                ),
            )
            Spacer(Modifier.height(4.dp))
            OutlinedTextField(
                deviceName, { deviceName = it },
                label = { Text("Name of this device") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            ErrorCard(model)
            Spacer(Modifier.height(16.dp))
            Button(
                onClick = {
                    if (server.length > 8 && code.isNotBlank()) {
                        model.error = null; step = 1
                    } else {
                        model.error = "Please fill in the server address and the code."
                    }
                },
                modifier = Modifier.fillMaxWidth().height(52.dp),
            ) { Text("Continue") }
        } else {
            PatternPad(presses, enabled = !model.busy)
            ErrorCard(model)
            if (model.busy) {
                Spacer(Modifier.height(8.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(
                    "Securing your keys and registering… this takes a few seconds.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 6.dp),
                )
            }
            Spacer(Modifier.height(16.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedButton(
                    onClick = { presses.clear(); first = null; step = 0; model.error = null },
                    enabled = !model.busy,
                    modifier = Modifier.weight(1f).height(52.dp),
                ) { Text("Back") }
                Button(
                    enabled = !model.busy && presses.size >= MIN_PRESSES,
                    onClick = {
                        val entered = presses.toList()
                        presses.clear()
                        when {
                            first == null -> { first = entered; model.error = null }
                            first != entered -> { first = null; model.error = "The patterns did not match. Please choose again." }
                            else -> model.register(server, code, withInvite, deviceName, entered)
                        }
                    },
                    modifier = Modifier.weight(1f).height(52.dp),
                ) { Text(if (first == null) "Next" else "Register") }
            }
        }
    }
}

@Composable
internal fun StepIndicator(current: Int) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        repeat(3) { index ->
            Box(
                Modifier
                    .weight(1f)
                    .height(4.dp)
                    .clip(CircleShape)
                    .background(
                        if (index <= current) MaterialTheme.colorScheme.primary
                        else MaterialTheme.colorScheme.surfaceContainerHighest,
                    ),
            )
        }
    }
}

@Composable
fun PendingScreen(model: AppModel, fingerprint: String) {
    FormScreen(
        AppIcons.Timer,
        "Waiting for approval",
        "Your device is registered. An administrator has to approve it before you can chat.",
    ) {
        Card(
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(16.dp)) {
                Text("Device fingerprint", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(4.dp))
                Text(
                    "Tell it to your administrator so they can verify this device.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.height(12.dp))
                Text(
                    fingerprint,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.titleMedium,
                    lineHeight = MaterialTheme.typography.titleMedium.lineHeight * 1.2,
                )
            }
        }
        ErrorCard(model)
        Spacer(Modifier.height(20.dp))
        Button(onClick = { model.refresh() }, enabled = !model.busy, modifier = Modifier.fillMaxWidth().height(52.dp)) {
            if (model.busy) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp) else Text("Check now")
        }
    }
}

@Composable
fun UnlockScreen(model: AppModel) {
    val presses = remember { mutableStateListOf<Int>() }
    FormScreen(AppIcons.Lock, "Secure Messenger", "Enter your pattern to unlock") {
        PatternPad(presses, enabled = !model.busy)
        ErrorCard(model)
        Spacer(Modifier.height(16.dp))
        Button(
            enabled = !model.busy && presses.isNotEmpty(),
            onClick = { val entered = presses.toList(); presses.clear(); model.unlock(entered) },
            modifier = Modifier.fillMaxWidth().height(52.dp),
        ) {
            if (model.busy) {
                CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.onPrimary)
                Spacer(Modifier.width(12.dp))
                Text("Unlocking…")
            } else {
                Text("Unlock")
            }
        }
    }
}

// ------------------------------------------------------------------ conversations

private fun conversationSubtitle(conv: FfiConversation): String =
    if (conv.isGroup) "Group · ${conv.members.size} members" else "Direct chat · end-to-end encrypted"

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ConversationsScreen(model: AppModel, onAllowBackground: () -> Unit = {}) {
    var newChat by remember { mutableStateOf(false) }
    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Chats", fontWeight = FontWeight.SemiBold)
                        model.username?.let {
                            Text(
                                "Signed in as $it",
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                },
                actions = {
                    IconButton(onClick = { model.lock() }) { Icon(AppIcons.Lock, "Lock") }
                    Box {
                        var menu by remember { mutableStateOf(false) }
                        IconButton(onClick = { menu = true }) { Icon(AppIcons.More, "More") }
                        DropdownMenu(menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("Refresh") },
                                leadingIcon = { Icon(AppIcons.Refresh, null) },
                                onClick = { menu = false; model.refresh() },
                            )
                            DropdownMenuItem(
                                text = { Text("Administration") },
                                leadingIcon = { Icon(AppIcons.Shield, null) },
                                onClick = { menu = false; model.openAdmin() },
                            )
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = { newChat = true },
                icon = { Icon(AppIcons.Edit, null) },
                text = { Text("New chat") },
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = model.busy,
            onRefresh = { model.refresh() },
            modifier = Modifier.padding(padding).fillMaxSize(),
        ) {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(bottom = 96.dp)) {
                item { ErrorCard(model, Modifier.padding(horizontal = 16.dp)) }
                if (model.batteryRestricted) {
                    item {
                        Card(
                            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
                            modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                        ) {
                            Column(Modifier.padding(14.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(AppIcons.NotificationsOff, null)
                                    Spacer(Modifier.width(12.dp))
                                    Text(
                                        "Notifications come through a background connection to your server. " +
                                            "Allow it to run in the background, otherwise Android may pause it while the phone sleeps.",
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                                TextButton(onClick = onAllowBackground, modifier = Modifier.align(Alignment.End)) {
                                    Text("Allow")
                                }
                            }
                        }
                    }
                }
                if (model.conversations.isEmpty() && !model.busy) {
                    item { EmptyChats() }
                }
                items(model.conversations, key = { it.id }) { conv ->
                    ConversationRow(conv, unread = conv.id in model.unread) { model.openChat(conv) }
                }
            }
        }
    }
    if (newChat) {
        NewChatDialog(onDismiss = { newChat = false }) { names, group -> newChat = false; model.newChat(names, group) }
    }
}

@Composable
private fun EmptyChats() {
    Column(
        Modifier.fillMaxWidth().padding(top = 96.dp, start = 32.dp, end = 32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        IconBadge(AppIcons.Chat, size = 88)
        Spacer(Modifier.height(20.dp))
        Text("No conversations yet", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Text(
            "Start a chat with someone on your server. Everything you write is end-to-end encrypted.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ConversationRow(conv: FfiConversation, unread: Boolean, onClick: () -> Unit) {
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        leadingContent = { Avatar(conv.title, conv.isGroup) },
        headlineContent = {
            Text(
                conv.title,
                fontWeight = if (unread) FontWeight.Bold else FontWeight.Medium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        },
        supportingContent = {
            Text(
                if (unread) "New messages" else conversationSubtitle(conv),
                color = if (unread) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                fontWeight = if (unread) FontWeight.SemiBold else FontWeight.Normal,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        },
        trailingContent = {
            if (unread) {
                Badge(containerColor = MaterialTheme.colorScheme.primary) { Text("new") }
            } else {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(AppIcons.Timer, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.outline)
                    Spacer(Modifier.width(3.dp))
                    Text("${conv.retentionDays} d", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.outline)
                }
            }
        },
        colors = ListItemDefaults.colors(containerColor = Color.Transparent),
    )
}

@Composable
private fun NewChatDialog(onDismiss: () -> Unit, onCreate: (List<String>, Boolean) -> Unit) {
    var names by remember { mutableStateOf("") }
    var group by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onDismiss,
        icon = { Icon(if (group) AppIcons.Group else AppIcons.Edit, null) },
        title = { Text(if (group) "New group" else "New chat") },
        text = {
            Column {
                SingleChoiceSegmentedButtonRow(Modifier.fillMaxWidth()) {
                    SegmentedButton(!group, { group = false }, SegmentedButtonDefaults.itemShape(0, 2)) { Text("Direct") }
                    SegmentedButton(group, { group = true }, SegmentedButtonDefaults.itemShape(1, 2)) { Text("Group") }
                }
                Spacer(Modifier.height(16.dp))
                OutlinedTextField(
                    names, { names = it },
                    label = { Text(if (group) "Usernames" else "Username") },
                    supportingText = { if (group) Text("Separate several names with commas") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            Button(
                enabled = names.isNotBlank(),
                onClick = {
                    val list = names.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                    if (list.isNotEmpty()) onCreate(list, group || list.size > 1)
                },
            ) { Text("Start") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

// ------------------------------------------------------------------ chat

private val timeFormat = DateTimeFormatter.ofPattern("HH:mm")
private val dateFormat = DateTimeFormatter.ofPattern("EEEE, d MMMM yyyy")

private fun localTime(rfc3339: String) =
    runCatching { OffsetDateTime.parse(rfc3339).atZoneSameInstant(ZoneId.systemDefault()) }.getOrNull()

private fun dayLabel(date: LocalDate): String {
    val today = LocalDate.now()
    return when (ChronoUnit.DAYS.between(date, today)) {
        0L -> "Today"
        1L -> "Yesterday"
        else -> date.format(dateFormat)
    }
}

/** What the chat list shows: day separators and messages with grouping info. */
private sealed interface ChatItem {
    val key: String

    data class Day(val label: String) : ChatItem {
        override val key get() = "day-$label"
    }

    data class Message(val message: FfiMessage, val firstOfGroup: Boolean, val lastOfGroup: Boolean) : ChatItem {
        override val key get() = message.id
    }
}

private fun isBubble(m: FfiMessage) = m.kind == FfiMessageKind.TEXT || m.kind == FfiMessageKind.MEDIA

private fun chatItems(messages: List<FfiMessage>): List<ChatItem> {
    val items = mutableListOf<ChatItem>()
    var lastDay: LocalDate? = null
    messages.forEachIndexed { i, m ->
        val time = localTime(m.createdAt)
        val day = time?.toLocalDate()
        if (day != null && day != lastDay) {
            items += ChatItem.Day(dayLabel(day))
            lastDay = day
        }
        // Consecutive bubbles of one sender within 5 minutes form a group.
        fun sameGroup(a: FfiMessage?, b: FfiMessage?): Boolean {
            if (a == null || b == null || !isBubble(a) || !isBubble(b) || a.sender != b.sender || a.mine != b.mine) return false
            val ta = localTime(a.createdAt) ?: return false
            val tb = localTime(b.createdAt) ?: return false
            return ta.toLocalDate() == tb.toLocalDate() && kotlin.math.abs(ChronoUnit.MINUTES.between(ta, tb)) < 5
        }
        val prev = messages.getOrNull(i - 1)
        val next = messages.getOrNull(i + 1)
        items += ChatItem.Message(m, firstOfGroup = !sameGroup(prev, m), lastOfGroup = !sameGroup(m, next))
    }
    return items
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ChatScreen(model: AppModel, conversation: FfiConversation) {
    var text by remember { mutableStateOf("") }
    var toDelete by remember { mutableStateOf<FfiMessage?>(null) }
    var dialog by remember { mutableStateOf<String?>(null) }
    var menu by remember { mutableStateOf(false) }
    var confirmSave by remember { mutableStateOf<FfiMessage?>(null) }
    var saving by remember { mutableStateOf<FfiMessage?>(null) }
    var viewing by remember { mutableStateOf<FfiMessage?>(null) }
    // Selection mode: ids of selected messages; `allSelected` means the
    // whole chat (also older messages not loaded yet).
    val selected = remember(conversation.id) { mutableStateListOf<String>() }
    var allSelected by remember(conversation.id) { mutableStateOf(false) }
    var confirmBulk by remember { mutableStateOf(false) }
    var confirmDeleteAll by remember { mutableStateOf(false) }
    val selecting = selected.isNotEmpty()
    fun toggle(id: String) {
        allSelected = false
        if (id in selected) selected.remove(id) else selected.add(id)
    }
    BackHandler(enabled = selecting) { selected.clear(); allSelected = false }
    // Back gesture / swipe from left to right closes the chat.
    BackHandler(enabled = !selecting) { model.closeChat() }
    val swipe = remember { Animatable(0f) }
    val swipeScope = rememberCoroutineScope()
    val screenWidth = with(LocalDensity.current) { LocalConfiguration.current.screenWidthDp.dp.toPx() }
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
    val items = remember(model.messages.toList()) { chatItems(model.messages) }
    val list = rememberLazyListState()
    LaunchedEffect(items.size) { if (items.isNotEmpty()) list.scrollToItem(items.size) }

    Scaffold(
        modifier = Modifier
            .imePadding()
            .offset { IntOffset(swipe.value.roundToInt(), 0) }
            .pointerInput(selecting) {
                if (selecting) return@pointerInput
                detectHorizontalDragGestures(
                    onDragEnd = {
                        swipeScope.launch {
                            if (swipe.value > screenWidth / 4) {
                                swipe.animateTo(screenWidth)
                                model.closeChat()
                            } else {
                                swipe.animateTo(0f)
                            }
                        }
                    },
                    onDragCancel = { swipeScope.launch { swipe.animateTo(0f) } },
                ) { change, amount ->
                    change.consume()
                    swipeScope.launch { swipe.snapTo((swipe.value + amount).coerceAtLeast(0f)) }
                }
            },
        topBar = {
            if (selecting) {
                TopAppBar(
                    navigationIcon = {
                        IconButton(onClick = { selected.clear(); allSelected = false }) { Icon(AppIcons.Close, "Cancel selection") }
                    },
                    title = { Text(if (allSelected) "All messages" else "${selected.size} selected") },
                    actions = {
                        IconButton(onClick = {
                            selected.clear()
                            selected.addAll(model.messages.filter { isBubble(it) }.map { it.id })
                            allSelected = true
                        }) { Icon(AppIcons.Check, "Select all") }
                        IconButton(onClick = { confirmBulk = true }) {
                            Icon(AppIcons.Delete, "Delete for everyone", tint = MaterialTheme.colorScheme.error)
                        }
                    },
                    colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.secondaryContainer),
                )
                return@Scaffold
            }
            TopAppBar(
                navigationIcon = { IconButton(onClick = { model.closeChat() }) { Icon(AppIcons.Back, "Back") } },
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Avatar(conversation.title, conversation.isGroup, size = 38)
                        Spacer(Modifier.width(12.dp))
                        Column {
                            Text(conversation.title, maxLines = 1, overflow = TextOverflow.Ellipsis, style = MaterialTheme.typography.titleMedium)
                            Text(
                                (if (conversation.isGroup) "${conversation.members.size} members · " else "") +
                                    "messages disappear after ${conversation.retentionDays} days",
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                            )
                        }
                    }
                },
                actions = {
                    Box {
                        IconButton(onClick = { menu = true }) { Icon(AppIcons.More, "More") }
                        DropdownMenu(menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("Retention period") },
                                leadingIcon = { Icon(AppIcons.Timer, null) },
                                onClick = { menu = false; dialog = "retention" },
                            )
                            DropdownMenuItem(
                                text = { Text("Select messages") },
                                leadingIcon = { Icon(AppIcons.Check, null) },
                                onClick = {
                                    menu = false
                                    model.messages.lastOrNull { isBubble(it) }?.let { selected.add(it.id) }
                                },
                            )
                            DropdownMenuItem(
                                text = { Text("Clear chat", color = MaterialTheme.colorScheme.error) },
                                leadingIcon = { Icon(AppIcons.Delete, null, tint = MaterialTheme.colorScheme.error) },
                                onClick = { menu = false; confirmDeleteAll = true },
                            )
                            if (conversation.isGroup && conversation.iAmAdmin) {
                                DropdownMenuItem(
                                    text = { Text("Invite someone") },
                                    leadingIcon = { Icon(AppIcons.PersonAdd, null) },
                                    onClick = { menu = false; dialog = "add" },
                                )
                            }
                            if (conversation.isGroup) {
                                DropdownMenuItem(
                                    text = { Text("Leave group") },
                                    leadingIcon = { Icon(AppIcons.Leave, null) },
                                    onClick = { menu = false; dialog = "leave" },
                                )
                            }
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surfaceContainer),
            )
        },
        bottomBar = {
            Composer(
                text = text,
                onText = { text = it },
                busy = model.busy,
                onAttach = {
                    model.pickerOpenedAt = SystemClock.elapsedRealtime()
                    attach.launch(arrayOf("*/*"))
                },
                onSend = { model.send(text.trim()); text = "" },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            ErrorCard(model, Modifier.padding(horizontal = 12.dp))
            LazyColumn(
                Modifier.weight(1f).fillMaxWidth(),
                state = list,
                contentPadding = PaddingValues(horizontal = 10.dp, vertical = 8.dp),
            ) {
                if (model.olderCursor != null) {
                    item(key = "older") {
                        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                            TextButton(onClick = { model.loadOlder() }) { Text("Load older messages") }
                        }
                    }
                }
                items(items, key = { it.key }) { item ->
                    when (item) {
                        is ChatItem.Day -> DayChip(item.label)
                        is ChatItem.Message -> MessageRow(
                            item,
                            selecting = selecting,
                            isSelected = item.message.id in selected,
                            onToggle = { toggle(item.message.id) },
                            showSender = conversation.isGroup,
                            preview = model.previews[item.message.id],
                            onNeedPreview = { model.loadPreview(item.message) },
                            onOpen = { viewing = item.message; model.openImage(item.message) },
                            onSave = { confirmSave = item.message },
                            onDelete = { toDelete = item.message },
                        )
                    }
                }
            }
        }
    }

    toDelete?.let { message ->
        AlertDialog(
            onDismissRequest = { toDelete = null },
            icon = { Icon(AppIcons.Delete, null) },
            title = { Text("Delete for everyone?") },
            text = { Text("The message is removed for all participants. Copies someone exported or photographed cannot be recalled.") },
            confirmButton = {
                TextButton(onClick = { toDelete = null; model.deleteForEveryone(message) }) {
                    Text("Delete for everyone", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = { TextButton(onClick = { toDelete = null }) { Text("Cancel") } },
        )
    }
    if (confirmBulk) {
        val count = selected.size
        AlertDialog(
            onDismissRequest = { confirmBulk = false },
            icon = { Icon(AppIcons.Delete, null) },
            title = {
                Text(
                    when {
                        allSelected -> "Delete all messages for everyone?"
                        count == 1 -> "Delete this message for everyone?"
                        else -> "Delete $count messages for everyone?"
                    },
                )
            },
            text = {
                Text(
                    (if (allSelected) "Every message in this chat is removed for all participants, also older ones not shown yet. " else "They are removed for all participants. ") +
                        "Copies someone exported or photographed cannot be recalled.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        confirmBulk = false
                        if (allSelected) model.deleteAllMessages() else model.deleteMessages(selected.toList())
                        selected.clear()
                        allSelected = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError),
                ) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { confirmBulk = false }) { Text("Cancel") } },
        )
    }
    if (confirmDeleteAll) {
        AlertDialog(
            onDismissRequest = { confirmDeleteAll = false },
            icon = { Icon(AppIcons.Delete, null) },
            title = { Text("Clear this chat for everyone?") },
            text = {
                Text(
                    "All messages you can see are removed for all participants, together with the " +
                        "\"message deleted\" placeholders and older notices. A note says that you cleared the chat. " +
                        "This cannot be undone.",
                )
            },
            confirmButton = {
                Button(
                    onClick = { confirmDeleteAll = false; model.clearChat() },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error, contentColor = MaterialTheme.colorScheme.onError),
                ) { Text("Clear chat") }
            },
            dismissButton = { TextButton(onClick = { confirmDeleteAll = false }) { Text("Cancel") } },
        )
    }
    confirmSave?.let { message ->
        AlertDialog(
            onDismissRequest = { confirmSave = null },
            icon = { Icon(AppIcons.Download, null) },
            title = { Text("Save ${message.media?.name ?: "file"}?") },
            text = { Text("A saved copy is outside the app: deleting the message for everyone later will not remove it, and it is not encrypted on the device.") },
            confirmButton = {
                Button(onClick = {
                    confirmSave = null
                    saving = message
                    model.pickerOpenedAt = SystemClock.elapsedRealtime()
                    saveTo.launch(message.media?.name ?: "file")
                }) { Text("Save") }
            },
            dismissButton = { TextButton(onClick = { confirmSave = null }) { Text("Cancel") } },
        )
    }
    model.viewer?.let { image ->
        ImageViewer(
            image,
            title = viewing?.media?.name.orEmpty(),
            onClose = { model.viewer = null; viewing = null },
            onSave = viewing?.let { m -> { model.viewer = null; viewing = null; confirmSave = m } },
        )
    }
    when (dialog) {
        "retention" -> InputDialog(
            AppIcons.Timer, "Retention period",
            "Messages are deleted for everyone after this many days (1–365). All members see the change.",
            conversation.retentionDays.toString(), KeyboardType.Number, onDismiss = { dialog = null },
        ) { value ->
            dialog = null
            value.toIntOrNull()?.takeIf { it in 1..365 }?.let { model.setRetention(it) }
                ?: run { model.error = "Please enter 1–365 days." }
        }
        "add" -> InputDialog(AppIcons.PersonAdd, "Invite to group", "Username of the person to add:", "", KeyboardType.Text,
            onDismiss = { dialog = null }) { value ->
            dialog = null; model.addMember(value)
        }
        "leave" -> AlertDialog(
            onDismissRequest = { dialog = null },
            icon = { Icon(AppIcons.Leave, null) },
            title = { Text("Leave this group?") },
            text = { Text("You will no longer see its messages.") },
            confirmButton = { TextButton(onClick = { dialog = null; model.leave() }) { Text("Leave") } },
            dismissButton = { TextButton(onClick = { dialog = null }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun DayChip(label: String) {
    Box(Modifier.fillMaxWidth().padding(vertical = 10.dp), contentAlignment = Alignment.Center) {
        Surface(shape = CircleShape, color = MaterialTheme.colorScheme.surfaceContainerHigh) {
            Text(
                label,
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
            )
        }
    }
}

@Composable
private fun Composer(text: String, onText: (String) -> Unit, busy: Boolean, onAttach: () -> Unit, onSend: () -> Unit) {
    Surface(color = MaterialTheme.colorScheme.surfaceContainer) {
        Row(
            Modifier.fillMaxWidth().navigationBarsPadding().padding(horizontal = 8.dp, vertical = 8.dp),
            verticalAlignment = Alignment.Bottom,
        ) {
            Surface(
                shape = RoundedCornerShape(26.dp),
                color = MaterialTheme.colorScheme.surfaceContainerHighest,
                modifier = Modifier.weight(1f),
            ) {
                Row(verticalAlignment = Alignment.Bottom) {
                    IconButton(onClick = onAttach, enabled = !busy, modifier = Modifier.padding(bottom = 2.dp)) {
                        Icon(AppIcons.Attach, "Attach a file", tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextField(
                        text, onText,
                        placeholder = { Text("Message") },
                        maxLines = 5,
                        modifier = Modifier.weight(1f).heightIn(min = 52.dp),
                        keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                        colors = TextFieldDefaults.colors(
                            focusedContainerColor = Color.Transparent,
                            unfocusedContainerColor = Color.Transparent,
                            disabledContainerColor = Color.Transparent,
                            focusedIndicatorColor = Color.Transparent,
                            unfocusedIndicatorColor = Color.Transparent,
                        ),
                    )
                }
            }
            Spacer(Modifier.width(8.dp))
            FilledIconButton(
                onClick = onSend,
                enabled = text.isNotBlank() && !busy,
                modifier = Modifier.size(52.dp),
                colors = IconButtonDefaults.filledIconButtonColors(),
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                } else {
                    Icon(AppIcons.Send, "Send")
                }
            }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
private fun MessageRow(
    item: ChatItem.Message,
    selecting: Boolean,
    isSelected: Boolean,
    onToggle: () -> Unit,
    showSender: Boolean,
    preview: ImageBitmap?,
    onNeedPreview: () -> Unit,
    onOpen: () -> Unit,
    onSave: () -> Unit,
    onDelete: () -> Unit,
) {
    val message = item.message
    if (!isBubble(message)) {
        NoticePill(message)
        return
    }
    val mine = message.mine
    var menu by remember { mutableStateOf(false) }
    val big = 20.dp
    val small = 6.dp
    // Inside a group of messages the corners on the sender's side are tight.
    val top = if (item.firstOfGroup) big else small
    val bottom = if (item.lastOfGroup) big else small
    val shape = if (mine) RoundedCornerShape(big, top, bottom, big) else RoundedCornerShape(top, big, big, bottom)
    val bubbleColor = if (mine) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.surfaceContainerHigh
    val textColor = if (mine) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface
    val media = message.media

    Row(
        Modifier
            .fillMaxWidth()
            .padding(top = if (item.firstOfGroup) 8.dp else 2.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(if (isSelected) MaterialTheme.colorScheme.primary.copy(alpha = 0.22f) else Color.Transparent)
            .then(if (selecting) Modifier.clickable(onClick = onToggle) else Modifier),
        verticalAlignment = Alignment.CenterVertically,
    ) {
    if (selecting) SelectionCircle(isSelected)
    Column(Modifier.weight(1f), horizontalAlignment = if (mine) Alignment.End else Alignment.Start) {
        if (showSender && !mine && item.firstOfGroup) {
            Text(
                message.sender,
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.SemiBold,
                color = colorFor(message.sender),
                modifier = Modifier.padding(start = 12.dp, bottom = 2.dp),
            )
        }
        Box {
            Surface(
                shape = shape,
                color = bubbleColor,
                contentColor = textColor,
                modifier = Modifier
                    .widthIn(max = 300.dp)
                    .clip(shape)
                    .combinedClickable(
                        onClick = { if (selecting) onToggle() else if (media?.kind == FfiMediaKind.IMAGE) onOpen() },
                        onLongClick = { if (selecting) onToggle() else menu = true },
                    ),
            ) {
                val caption = message.text
                val time = localTime(message.createdAt)?.format(timeFormat).orEmpty()
                Column(Modifier.padding(if (media?.hasPreview == true) 4.dp else 0.dp)) {
                    if (media != null) {
                        if (media.hasPreview) {
                            LaunchedEffect(message.id) { onNeedPreview() }
                            Box {
                                ImagePreview(preview, media.name)
                                // Without a caption the time sits on the picture.
                                if (caption.isEmpty()) {
                                    Text(
                                        time,
                                        style = MaterialTheme.typography.labelSmall,
                                        color = Color.White,
                                        modifier = Modifier
                                            .align(Alignment.BottomEnd)
                                            .padding(8.dp)
                                            .background(Color.Black.copy(alpha = 0.45f), CircleShape)
                                            .padding(horizontal = 8.dp, vertical = 2.dp),
                                    )
                                }
                            }
                        } else {
                            FileCard(media.name, media.size, mine, onSave)
                        }
                    }
                    if (media?.hasPreview == true && caption.isEmpty()) return@Column
                    Row(
                        Modifier.padding(
                            start = 12.dp, end = 10.dp,
                            top = if (media != null && caption.isEmpty()) 2.dp else 8.dp, bottom = 6.dp,
                        ),
                        verticalAlignment = Alignment.Bottom,
                    ) {
                        if (caption.isNotEmpty()) {
                            Text(caption, style = MaterialTheme.typography.bodyLarge, modifier = Modifier.weight(1f, fill = false))
                            Spacer(Modifier.width(8.dp))
                        }
                        Text(
                            time,
                            style = MaterialTheme.typography.labelSmall,
                            color = textColor.copy(alpha = 0.7f),
                        )
                    }
                }
            }
            DropdownMenu(menu, onDismissRequest = { menu = false }) {
                DropdownMenuItem(
                    text = { Text("Select") },
                    leadingIcon = { Icon(AppIcons.Check, null) },
                    onClick = { menu = false; onToggle() },
                )
                if (media != null) {
                    if (media.kind == FfiMediaKind.IMAGE) {
                        DropdownMenuItem(text = { Text("Open") }, onClick = { menu = false; onOpen() })
                    }
                    DropdownMenuItem(
                        text = { Text("Save to device") },
                        leadingIcon = { Icon(AppIcons.Download, null) },
                        onClick = { menu = false; onSave() },
                    )
                }
                DropdownMenuItem(
                    text = { Text("Delete for everyone", color = MaterialTheme.colorScheme.error) },
                    leadingIcon = { Icon(AppIcons.Delete, null, tint = MaterialTheme.colorScheme.error) },
                    onClick = { menu = false; onDelete() },
                )
            }
        }
    }
    }
}

/** Check circle shown next to each message in selection mode. */
@Composable
private fun SelectionCircle(selected: Boolean) {
    Box(
        Modifier
            .padding(start = 6.dp, end = 8.dp)
            .size(24.dp)
            .clip(CircleShape)
            .background(if (selected) MaterialTheme.colorScheme.primary else Color.Transparent),
        contentAlignment = Alignment.Center,
    ) {
        if (selected) {
            Icon(AppIcons.Check, null, Modifier.size(16.dp), tint = MaterialTheme.colorScheme.onPrimary)
        } else {
            Box(
                Modifier
                    .size(22.dp)
                    .border(2.dp, MaterialTheme.colorScheme.outline, CircleShape),
            )
        }
    }
}

@Composable
private fun ImagePreview(preview: ImageBitmap?, name: String) {
    val shape = RoundedCornerShape(16.dp)
    if (preview != null) {
        Image(
            preview,
            contentDescription = name,
            contentScale = ContentScale.Crop,
            modifier = Modifier
                .width(260.dp)
                .aspectRatio((preview.width.toFloat() / preview.height).coerceIn(0.6f, 2f))
                .clip(shape),
        )
    } else {
        Box(
            Modifier.width(260.dp).height(180.dp).clip(shape).background(MaterialTheme.colorScheme.surfaceContainerHighest),
            contentAlignment = Alignment.Center,
        ) {
            CircularProgressIndicator(Modifier.size(28.dp), strokeWidth = 2.dp)
        }
    }
}

@Composable
private fun FileCard(name: String, size: ULong, mine: Boolean, onSave: () -> Unit) {
    val tint = if (mine) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.primary
    Row(Modifier.padding(start = 10.dp, end = 4.dp, top = 10.dp), verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier.size(42.dp).background(tint.copy(alpha = 0.15f), RoundedCornerShape(12.dp)),
            contentAlignment = Alignment.Center,
        ) { Icon(AppIcons.File, null, tint = tint) }
        Spacer(Modifier.width(10.dp))
        Column(Modifier.widthIn(max = 170.dp)) {
            Text(name, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(humanSize(size), style = MaterialTheme.typography.labelSmall)
        }
        IconButton(onClick = onSave) { Icon(AppIcons.Download, "Save", tint = tint) }
    }
}

@Composable
private fun NoticePill(message: FfiMessage) {
    val warning = message.kind == FfiMessageKind.UNAVAILABLE || message.kind == FfiMessageKind.UNDECRYPTABLE
    Box(Modifier.fillMaxWidth().padding(vertical = 6.dp, horizontal = 24.dp), contentAlignment = Alignment.Center) {
        Surface(
            shape = RoundedCornerShape(12.dp),
            color = if (warning) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceContainer,
        ) {
            Row(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalAlignment = Alignment.CenterVertically) {
                if (message.kind == FfiMessageKind.DELETED) {
                    Icon(AppIcons.Delete, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                    Spacer(Modifier.width(6.dp))
                } else if (warning) {
                    Icon(AppIcons.Warning, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.onErrorContainer)
                    Spacer(Modifier.width(6.dp))
                }
                Text(
                    message.text,
                    style = MaterialTheme.typography.labelMedium,
                    fontStyle = if (message.kind == FfiMessageKind.NOTICE) FontStyle.Normal else FontStyle.Italic,
                    color = if (warning) MaterialTheme.colorScheme.onErrorContainer else MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}

@Composable
private fun ImageViewer(image: ImageBitmap, title: String, onClose: () -> Unit, onSave: (() -> Unit)?) {
    Dialog(onDismissRequest = onClose, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Box(Modifier.fillMaxSize().background(Color.Black)) {
            Image(image, contentDescription = title, modifier = Modifier.fillMaxSize(), contentScale = ContentScale.Fit)
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(Color.Black.copy(alpha = 0.45f))
                    .statusBarsPadding()
                    .padding(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(onClick = onClose) { Icon(AppIcons.Close, "Close", tint = Color.White) }
                Text(title, color = Color.White, maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f))
                if (onSave != null) {
                    IconButton(onClick = onSave) { Icon(AppIcons.Download, "Save", tint = Color.White) }
                }
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
    icon: ImageVector,
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
        icon = { Icon(icon, null) },
        title = { Text(title) },
        text = {
            Column {
                Text(label, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.height(12.dp))
                OutlinedTextField(
                    value, { value = it },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = keyboard),
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = { Button(onClick = { onConfirm(value.trim()) }, enabled = value.isNotBlank()) { Text("OK") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
