package com.example.p2pdemo

import android.app.Application
import android.content.Context

/**
 * 进程级容器：会话生命周期比 Activity 长（虚拟网卡运行在 VpnService 里），
 * 所以控制器放在 Application，Activity 和服务都取同一个实例。
 */
class MeshApp : Application() {

    val controller: MeshController by lazy { MeshController(this) }
}

fun meshController(context: Context): MeshController =
    (context.applicationContext as MeshApp).controller
