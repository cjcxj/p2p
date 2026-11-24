package com.example.p2pdemo

import android.content.Context

/** 连接参数持久化：只有一份读写逻辑，UI 和服务都从这里取。 */
object Prefs {

    private const val NAME = "mesh_prefs"

    private const val KEY_SERVER = "server"
    private const val KEY_ROOM = "room"
    private const val KEY_TOKEN = "token"
    private const val KEY_USER = "user"
    private const val KEY_SECRET = "secret"
    private const val KEY_RELAY = "relay"
    private const val KEY_DEBUG = "debug"
    private const val KEY_PLAINTEXT = "plaintext"
    private const val KEY_LEGACY = "legacy_mesh"
    private const val KEY_TARGET = "target_ip"

    fun load(context: Context): ConnConfig {
        val p = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
        return ConnConfig(
            serverAddr = p.getString(KEY_SERVER, "").orEmpty().trim(),
            room = p.getString(KEY_ROOM, DEFAULT_ROOM).orEmpty().trim(),
            token = p.getString(KEY_TOKEN, "").orEmpty().trim(),
            authUser = p.getString(KEY_USER, "").orEmpty().trim(),
            authSecret = p.getString(KEY_SECRET, "").orEmpty().trim(),
            relayEnabled = p.getBoolean(KEY_RELAY, true),
            debug = p.getBoolean(KEY_DEBUG, true),
            plaintext = p.getBoolean(KEY_PLAINTEXT, false),
            legacyMesh = p.getBoolean(KEY_LEGACY, false),
        )
    }

    fun save(context: Context, cfg: ConnConfig) {
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE).edit()
            .putString(KEY_SERVER, cfg.serverAddr.trim())
            .putString(KEY_ROOM, cfg.room.trim())
            .putString(KEY_TOKEN, cfg.token.trim())
            .putString(KEY_USER, cfg.authUser.trim())
            .putString(KEY_SECRET, cfg.authSecret.trim())
            .putBoolean(KEY_RELAY, cfg.relayEnabled)
            .putBoolean(KEY_DEBUG, cfg.debug)
            .putBoolean(KEY_PLAINTEXT, cfg.plaintext)
            .putBoolean(KEY_LEGACY, cfg.legacyMesh)
            .apply()
    }

    fun loadTarget(context: Context): String =
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
            .getString(KEY_TARGET, "").orEmpty()

    fun saveTarget(context: Context, ip: String) {
        context.getSharedPreferences(NAME, Context.MODE_PRIVATE)
            .edit().putString(KEY_TARGET, ip).apply()
    }

    const val DEFAULT_ROOM = "demo"
}
