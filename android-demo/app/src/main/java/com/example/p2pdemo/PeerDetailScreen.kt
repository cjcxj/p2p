package com.example.p2pdemo

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/**
 * 单个节点的详情页。从节点列表点进来，展示链路/NAT/端点等全部字段，并提供
 * "设为测试目标"和"发起 ping"两个动作，替代以前只能在列表里点一下就设目标的
 * 简略交互。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PeerDetailScreen(
    row: PeerRow,
    onBack: () -> Unit,
    onSetTarget: () -> Unit,
    onPing: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(row.virtualIp.ifEmpty { "未分配" }, fontFamily = FontFamily.Monospace) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.Menu, contentDescription = "返回")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                LinkBadge(row)
                Spacer(Modifier.width(10.dp))
                Text(row.linkLabel, style = MaterialTheme.typography.titleMedium)
            }

            SectionCard(title = "链路") {
                InfoRow("虚拟 IP", row.virtualIp.ifEmpty { "未分配" })
                InfoRow("节点 ID", row.peerId)
                InfoRow("UDP 端点", row.endpoint)
                InfoRow("NAT 类型", row.natType)
                InfoRow("传输", row.transport)
            }

            if (!row.isDirect && row.connected) {
                Hint("中继节点不进入 WireGuard 隧道：隧道只走打洞成功的直连链路。")
            } else if (row.isDirect) {
                Hint("直连成功：流量在两端点对点加密传输，不经服务器。")
            }

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Button(onClick = onSetTarget, modifier = Modifier.weight(1f)) { Text("设为测试目标") }
                OutlinedButton(onClick = onPing, modifier = Modifier.weight(1f)) { Text("ping") }
            }
        }
    }
}
