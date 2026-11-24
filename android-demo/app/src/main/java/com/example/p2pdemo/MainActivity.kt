package com.example.p2pdemo

import android.Manifest
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts

/**
 * 界面宿主。它只做系统才允许的两件事：申请 VPN 授权、申请通知权限，
 * 组网本身全部交给 [MeshController]——Activity 里不再藏第二个会话。
 */
class MainActivity : ComponentActivity() {

    private var pendingAfterConsent: (() -> Unit)? = null

    private val consent = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val action = pendingAfterConsent
        pendingAfterConsent = null
        if (result.resultCode == RESULT_OK) {
            action?.invoke()
        } else {
            meshController(this).appendExternalLog("VPN 授权被拒绝，虚拟网卡无法开启")
        }
    }

    private val notifications = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            meshController(this).appendExternalLog("没有通知权限，前台服务通知不会显示")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        askNotificationPermission()
        val controller = meshController(this)
        setContent {
            MeshTheme {
                MainScreen(controller = controller, requestVpn = { requestVpn(controller) })
            }
        }
    }

    /**
     * 开虚拟网卡：先问系统要权限，再把服务拉起来。
     * 服务只负责提供 protect/establish 能力，连房间和挂隧道由控制器的 startAll 完成。
     */
    private fun requestVpn(controller: MeshController) {
        val consentIntent = try {
            VpnService.prepare(this)
        } catch (e: Exception) {
            controller.appendExternalLog("检查 VPN 授权失败：${e.message}")
            return
        }
        if (consentIntent == null) {
            MeshVpnService.start(this)
            return
        }
        pendingAfterConsent = { MeshVpnService.start(this) }
        try {
            consent.launch(consentIntent)
        } catch (e: Exception) {
            pendingAfterConsent = null
            Log.e(TAG, "无法打开授权界面: ${e.message}")
            controller.appendExternalLog("系统授权界面打不开，请在设置里手动允许“创建 VPN 连接”")
        }
    }

    private fun askNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            try {
                notifications.launch(Manifest.permission.POST_NOTIFICATIONS)
            } catch (e: Exception) {
                Log.w(TAG, "申请通知权限失败: ${e.message}")
            }
        }
    }

    private companion object {
        const val TAG = "MeshMain"
    }
}
