package com.example.p2pdemo

import android.widget.Toast
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * 主界面。数据全部来自 [MeshController] 的 StateFlow，这里只负责显示和把操作交给控制器，
 * 因此不存在旧版那种“Activity 自己一套状态、服务另一套状态”的分叉。
 *
 * @param requestVpn 打开虚拟网卡的入口，由 Activity 提供——只有它能弹系统 VPN 授权框。
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(controller: MeshController, requestVpn: () -> Unit) {
    val state by controller.state.collectAsState()
    val logs by controller.logs.collectAsState()
    val context = LocalContext.current

    var showSettings by remember { mutableStateOf(false) }
    var detail by remember { mutableStateOf<PeerRow?>(null) }
    val tabs = listOf("控制", "状态", "节点", "工具", "日志")
    val pager = rememberPagerState(pageCount = { tabs.size })
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("P2P 组网") },
                actions = {
                    IconButton(onClick = { showSettings = true }) {
                        Icon(Icons.Default.Settings, contentDescription = "连接参数")
                    }
                },
            )
        },
        bottomBar = {
            NavigationBar {
                val icons = listOf(
                    Icons.Default.Settings, Icons.Default.Info, Icons.Default.List,
                    Icons.Default.Refresh, Icons.Default.Menu,
                )
                tabs.forEachIndexed { index, label ->
                    NavigationBarItem(
                        selected = pager.currentPage == index,
                        onClick = { scope.launch { pager.animateScrollToPage(index) } },
                        icon = { Icon(icons[index], contentDescription = label) },
                        label = { Text(label) },
                    )
                }
            }
        },
    ) { padding ->
        HorizontalPager(
            state = pager,
            modifier = Modifier
                .padding(padding)
                .fillMaxSize(),
        ) { page ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 12.dp, vertical = 8.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                when (page) {
                    0 -> StatusCard(
                        state = state,
                        onTunnel = { on ->
                            if (on) {
                                if (!state.config.isValid) {
                                    Toast.makeText(context, "请先填写服务器地址和房间", Toast.LENGTH_SHORT).show()
                                } else {
                                    requestVpn()
                                }
                            } else {
                                controller.setTunnel(false)
                            }
                        },
                        onConnect = { controller.connect() },
                        onDisconnect = { controller.disconnect() },
                        onRefresh = { controller.refreshNow() },
                    )
                    1 -> OverviewTab(state)
                    2 -> PeersTab(state) { row -> detail = row }
                    3 -> ToolsTab(state, controller)
                    else -> LogsTab(logs, controller)
                }
            }
        }
    }

    detail?.let { row ->
        PeerDetailScreen(
            row = row,
            onBack = { detail = null },
            onSetTarget = {
                controller.selectTarget(row.virtualIp)
                Toast.makeText(context, "测试目标：${row.virtualIp}", Toast.LENGTH_SHORT).show()
                detail = null
            },
            onPing = {
                controller.selectTarget(row.virtualIp)
                controller.runPing()
                detail = null
            },
        )
    }

    if (showSettings) {
        SettingsSheet(
            current = state.config,
            onDismiss = { showSettings = false },
            onSave = {
                controller.saveConfig(it)
                showSettings = false
            },
        )
    }
}

@Composable
private fun StatusCard(
    state: MeshUiState,
    onTunnel: (Boolean) -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onRefresh: () -> Unit,
) {
    SectionCard(title = "本机", trailing = { IconButton(onClick = onRefresh) { Icon(Icons.Default.Refresh, "刷新") } }) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            PhaseBadge(state.phase)
            Spacer(Modifier.width(10.dp))
            Hint(
                text = when (state.tunnel) {
                    TunnelPhase.On -> "虚拟网卡 ${state.tunName}"
                    TunnelPhase.Starting -> "虚拟网卡建立中…"
                    TunnelPhase.Off -> "虚拟网卡未开启"
                }
            )
        }
        InfoRow("虚拟 IP", state.localIp)
        InfoRow("子网", state.subnet)
        InfoRow("NAT", state.natType)
        InfoRow("节点", "${state.peers.size} 个（直连 ${state.directPeers}）")

        HorizontalDivider(Modifier.padding(vertical = 4.dp))

        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("接入组网虚拟网卡", style = MaterialTheme.typography.bodyLarge)
                Hint("打开后本机获得虚拟 IP，可直接 ping / 连对端；关闭只收掉网卡，房间保持")
            }
            Switch(
                checked = state.tunnel != TunnelPhase.Off,
                onCheckedChange = onTunnel,
                enabled = !state.busy,
            )
        }

        if (state.error.isNotEmpty()) {
            Text(
                text = state.error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Button(
                onClick = onConnect,
                enabled = !state.busy && state.phase != SessionPhase.Connected,
                modifier = Modifier.weight(1f),
            ) { Text(if (state.hasSession) "重连房间" else "接入房间") }
            OutlinedButton(
                onClick = onDisconnect,
                enabled = state.hasSession,
                modifier = Modifier.weight(1f),
            ) { Text("离开房间") }
        }
    }
}

@Composable
private fun OverviewTab(state: MeshUiState) {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SectionCard(title = "链路") {
            InfoRow("本机会话 ID", shortId(state.localId))
            InfoRow("房间", state.config.room)
            InfoRow("服务器", state.config.serverAddr)
            InfoRow("数据面", if (state.config.legacyMesh) "旧版逐包转发（A/B）" else "WireGuard 隧道")
        }
        SectionCard(title = "怎么用") {
            Hint("1. 另一台设备填同一个服务器地址和房间名接入。")
            Hint("2. 节点列表点一个节点，把它设为测试目标。")
            Hint("3. 打开“接入组网虚拟网卡”，再到工具页 ping 或连 TCP 7000。")
            Hint("隧道由内核收发，ping 和 7000 端口无需在应用里实现；两端都要开虚拟网卡才能互通。")
        }
    }
}

@Composable
private fun PeersTab(state: MeshUiState, onOpen: (PeerRow) -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        if (state.peers.isEmpty()) {
            EmptyHint(
                if (state.hasSession) "房间里还没有其他节点：在另一台设备填同样的服务器地址与房间名接入。"
                else "还没有接入房间。"
            )
        } else {
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                contentPadding = PaddingValues(bottom = 12.dp),
            ) {
                items(state.peers, key = { it.virtualIp + it.peerId }) { row ->
                    PeerCard(row, selected = row.virtualIp == state.targetIp, onOpen = { onOpen(row) })
                }
            }
        }
    }
}

@Composable
private fun PeerCard(row: PeerRow, selected: Boolean, onOpen: () -> Unit) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = row.virtualIp.ifEmpty { "未分配" },
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.width(10.dp))
                LinkBadge(row)
                if (selected) {
                    Spacer(Modifier.width(8.dp))
                    Text("测试目标", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                }
            }
            InfoRow("节点 ID", shortId(row.peerId))
            InfoRow("UDP 地址", row.endpoint)
            InfoRow("NAT", row.natType)
            if (!row.isDirect && row.connected) {
                Hint("中继节点不进入隧道：隧道只走打洞成功的直连链路。")
            }
        }
    }
}

@Composable
private fun ToolsTab(state: MeshUiState, controller: MeshController) {
    Column(
        modifier = Modifier.fillMaxSize().padding(top = 10.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        SectionCard(title = "连通性自测") {
            InfoRow("目标", state.targetIp)
            Hint("测试从本机应用发出，流量真的经过虚拟网卡和隧道。")
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                FilledTonalButton(
                    onClick = { controller.runPing() },
                    enabled = state.targetIp.isNotEmpty() && !state.test.running,
                    modifier = Modifier.weight(1f),
                ) { Text("ping") }
                FilledTonalButton(
                    onClick = { controller.runEcho() },
                    enabled = state.targetIp.isNotEmpty() && !state.test.running,
                    modifier = Modifier.weight(1f),
                ) { Text("TCP ${MeshController.ECHO_PORT}") }
            }
            if (state.targetIp.isEmpty()) {
                Hint("先在节点页点选一个节点作为目标。")
            }
        }

        SectionCard(title = "最近结果") {
            val test = state.test
            if (test.target.isEmpty()) {
                Hint("还没有测试记录。")
            } else {
                val kindLabel = if (test.kind == TestKind.Ping) "ping" else "tcp echo"
                InfoRow(
                    label = kindLabel,
                    value = if (test.running) "进行中…" else test.summary,
                    highlight = test.ok == true,
                )
                InfoRow("目标", test.target)
            }
        }

        SectionCard(title = "本机可被测试的服务") {
            InfoRow("ICMP", "内核应答（无需应用参与）")
            InfoRow("TCP", "${MeshController.ECHO_PORT} 端口回声，接入房间后自动监听")
            Hint("对端把本机 IP 设为目标即可反向验证。")
        }
    }
}

@Composable
private fun LogsTab(logs: List<LogLine>, controller: MeshController) {
    var filter by remember { mutableStateOf<Set<LogKind>>(emptySet()) }
    val visible = if (filter.isEmpty()) logs else logs.filter { it.kind in filter }
    val listState = rememberLazyListState()
    LaunchedEffect(visible.size) {
        if (visible.isNotEmpty()) listState.animateScrollToItem(visible.lastIndex)
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(top = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            LogKind.entries.forEach { kind ->
                val label = when (kind) {
                    LogKind.Info -> "信息"
                    LogKind.Punch -> "打洞"
                    LogKind.Tunnel -> "隧道"
                    LogKind.Error -> "错误"
                }
                AssistChip(
                    onClick = {
                        filter = if (kind in filter) filter - kind else filter + kind
                    },
                    label = { Text(label) },
                )
            }
            Spacer(Modifier.weight(1f))
            OutlinedButton(onClick = { controller.clearLogs() }) { Text("清空") }
        }
        if (filter.isNotEmpty()) {
            Hint("过滤：${filter.joinToString("、")}")
        }
        LazyColumn(state = listState, modifier = Modifier.fillMaxSize()) {
            items(visible) { line ->
                LogRow(line)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun LogRow(line: LogLine) {
    val color = when (line.kind) {
        LogKind.Error -> MaterialTheme.colorScheme.error
        LogKind.Punch -> MaterialTheme.colorScheme.onSurfaceVariant
        LogKind.Tunnel -> MaterialTheme.colorScheme.primary
        LogKind.Info -> MaterialTheme.colorScheme.onSurface
    }
    Row(Modifier.fillMaxWidth().padding(vertical = 5.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = timeOf(line.at),
            style = MaterialTheme.typography.labelSmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = line.text,
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = color,
            modifier = Modifier.weight(1f, fill = false),
        )
    }
}

private fun shortId(id: String): String = if (id.length <= 12) id else id.substring(0, 12) + "…"

private fun timeOf(millis: Long): String {
    val total = (millis / 1000L)
    val second = (total % 60L).toInt()
    val minute = ((total / 60L) % 60L).toInt()
    val hour = ((total / 3600L) % 24L).toInt()
    return String.format("%02d:%02d:%02d", hour, minute, second)
}
