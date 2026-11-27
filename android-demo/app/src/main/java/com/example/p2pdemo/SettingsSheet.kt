package com.example.p2pdemo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp

/**
 * 连接参数面板。字段与 [ConnConfig] 一一对应，保存即写盘、下次接入即生效。
 *
 * “旧版 mesh 数据面”是 A/B 开关：打开后走被替换掉的逐包路径，用来在真机上对比
 * 隧道切换前后有没有回退。默认关闭。
 */
@Composable
fun SettingsSheet(
    current: ConnConfig,
    onDismiss: () -> Unit,
    onSave: (ConnConfig) -> Unit,
) {
    var draft by remember { mutableStateOf(current) }

    AlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = { TextButton(onClick = { onSave(draft) }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
        title = { Text("连接参数") },
        text = {
            Column(
                modifier = Modifier
                    .widthIn(max = 460.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                TextField(
                    label = "服务器地址（host:port）",
                    value = draft.serverAddr,
                    placeholder = "例如 192.168.1.100:8080",
                    onChange = { draft = draft.copy(serverAddr = it.trim()) },
                )
                TextField(
                    label = "房间",
                    value = draft.room,
                    placeholder = "同一房间才能互通",
                    onChange = { draft = draft.copy(room = it.trim()) },
                )
                TextField(
                    label = "房间密钥（可选）",
                    value = draft.token,
                    onChange = { draft = draft.copy(token = it.trim()) },
                )
                TextField(
                    label = "用户名（服务器按用户鉴权时）",
                    value = draft.authUser,
                    onChange = { draft = draft.copy(authUser = it.trim()) },
                )
                TextField(
                    label = "密码 / 密钥",
                    value = draft.authSecret,
                    onChange = { draft = draft.copy(authSecret = it.trim()) },
                )
                TextField(
                    label = "扩展 STUN 服务器（可选，逗号分隔）",
                    value = draft.stunList,
                    placeholder = "留空则使用信令下发与内置多 STUN",
                    onChange = { draft = draft.copy(stunList = it.trim()) },
                )

                Spacer(Modifier.height(6.dp))

                Text(
                    text = "纯直连打洞模式（自动启用多 STUN / IPv6 / UPnP）",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                ToggleRow(
                    label = "详细打洞日志",
                    support = "把探测、候选地址、握手过程写进日志页",
                    checked = draft.debug,
                    onChange = { draft = draft.copy(debug = it) },
                )
                ToggleRow(
                    label = "关闭数据面加密",
                    support = "仅测试用，两端必须同时打开",
                    checked = draft.plaintext,
                    onChange = { draft = draft.copy(plaintext = it) },
                )
                ToggleRow(
                    label = "旧版 mesh 数据面",
                    support = "A/B 对照：回到逐包转发，用于比较隧道性能",
                    checked = draft.legacyMesh,
                    onChange = { draft = draft.copy(legacyMesh = it) },
                )
            }
        },
    )
}

@Composable
private fun TextField(
    label: String,
    value: String,
    onChange: (String) -> Unit,
    placeholder: String = "",
) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        placeholder = { if (placeholder.isNotEmpty()) Text(placeholder) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(
            autoCorrect = false,
            keyboardType = if (label.contains("地址")) KeyboardType.Uri else KeyboardType.Text,
        ),
        modifier = Modifier.fillMaxWidth(),
        textStyle = MaterialTheme.typography.bodyMedium,
    )
}

@Composable
private fun ToggleRow(
    label: String,
    support: String,
    checked: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = support,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
