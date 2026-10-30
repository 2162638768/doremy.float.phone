package app.floatphone.shell

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.Settings
import android.util.Base64
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.charset.StandardCharsets
import kotlin.concurrent.thread

/**
 * 文件桥：让 float 的网页插件通过 http://127.0.0.1:8791 读写 /sdcard/DSH。
 *
 * 协议（与 float-plugin/file-assistant.js 对应）：
 *   POST /api/fs  { op: "read" | "write", path, content?, confirm? }
 *   -> 200 { ok: true, data: "..." }  |  { ok: false, error: "CODE: 说明" }
 *
 * 安全边界由原生层兜底，不依赖网页端：
 *   - 只监听 127.0.0.1
 *   - 路径必须在 /sdcard/ 下，且不含 .. ，凭据目录一律拒绝
 *   - 写操作必须 confirm=true，且只能落在 /sdcard/DSH 下
 *
 * 依赖只有 Android SDK 自带的 org.json，无需在 build.gradle 里加任何东西。
 */
class FloatFsBridge(
    private val port: Int = 8791,
    private val token: String = "",
    private val requireConfirm: Boolean = true,
) {
    private val denyNames = setOf(".dsh", ".ssh", ".android")
    private val maxReadBytes = 8L * 1024 * 1024
    private val maxBinaryBytes = 6L * 1024 * 1024

    private val workspace: File by lazy {
        File(Environment.getExternalStorageDirectory(), "DSH").also { it.mkdirs() }
    }

    fun start() {
        thread(isDaemon = true, name = "float-fs-bridge") {
            try {
                ServerSocket(port, 8, InetAddress.getByName("127.0.0.1")).use { server ->
                    Log.i(TAG, "listening on 127.0.0.1:$port, workspace=${workspace.absolutePath}")
                    while (!server.isClosed) {
                        val socket = runCatching { server.accept() }.getOrNull() ?: break
                        // 单个请求出错不能拖垮整个桥：包一层，记日志后继续服务
                        runCatching { socket.use { handle(it) } }
                            .onFailure { Log.e(TAG, "request failed", it) }
                    }
                }
            } catch (error: Throwable) {
                Log.e(TAG, "bridge failed to start", error)
            }
        }
    }

    private fun handle(socket: Socket) {
        val input = socket.getInputStream()
        val headerBytes = readHeaders(input) ?: return reply(socket, 400, error = "BAD_REQUEST")
        val lines = String(headerBytes, StandardCharsets.ISO_8859_1).split("\r\n")
        val requestLine = lines.firstOrNull().orEmpty().split(' ')

        val headers = HashMap<String, String>()
        for (line in lines.drop(1)) {
            val colon = line.indexOf(':')
            if (colon > 0) headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
        }

        // 预检与跨源：网页是 https origin，访问本机 http 必过 CORS + Private Network 检查
        if (requestLine.getOrNull(0) == "OPTIONS") return reply(socket, 204, error = null)

        val method = requestLine.getOrNull(0)
        val route = requestLine.getOrNull(1)
        if (method != "POST" || route != "/api/fs") {
            return reply(socket, 404, error = "NO_ROUTE: $method $route")
        }
        if (token.isNotEmpty() && headers["authorization"] != "Bearer $token") {
            return reply(socket, 401, error = "UNAUTHORIZED: token 不匹配")
        }

        val length = headers["content-length"]?.toIntOrNull() ?: 0
        val bodyBytes = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(bodyBytes, offset, length - offset)
            if (read <= 0) break
            offset += read
        }

        val request = runCatching {
            JSONObject(String(bodyBytes, 0, offset, StandardCharsets.UTF_8))
        }.getOrNull() ?: return reply(socket, 400, error = "BAD_JSON")

        // 健康检查：不看 path，放在路径校验之前，用来确认装的是哪个版本
        val op = request.optString("op")
        if (op == "ping") return reply(socket, 200, data = "pong-v2")

        val devicePath = request.optString("path", "")
        val rejected = rejectReason(devicePath)
        if (rejected != null) return reply(socket, 403, error = rejected)

        val target = runCatching { File(devicePath).canonicalFile }.getOrNull()
            ?: return reply(socket, 400, error = "BAD_PATH: $devicePath")

        when (request.optString("op")) {
            "read" -> readFile(socket, devicePath, target)
            "write" -> writeFile(socket, devicePath, target, request)
            "readBytes" -> readBinary(socket, devicePath, target)
            "writeBytes" -> writeBinary(socket, devicePath, target, request)
            "list" -> listDir(socket, devicePath, target)
            "stat" -> statFile(socket, devicePath, target)
            else -> reply(socket, 400, error = "UNKNOWN_OP: ${request.optString("op")}")
        }
    }

    /** 返回拒绝原因，允许则返回 null。所有检查都在原生长度上再做一遍。 */
    private fun rejectReason(devicePath: String): String? {
        if (devicePath.isEmpty()) return "BAD_PATH: 缺少 path"
        if (!devicePath.startsWith("/sdcard/")) return "PATH_NOT_ALLOWED: 只允许 /sdcard/ 下的路径"
        if (devicePath.split('/').any { it == ".." }) return "PATH_TRAVERSAL: 路径不能包含 .."
        for (segment in devicePath.split('/')) {
            if (segment.lowercase() in denyNames) return "PATH_DENIED: 凭据目录 \"$segment\" 不允许访问"
        }
        return null
    }

    private fun readFile(socket: Socket, devicePath: String, target: File) {
        if (!target.exists()) return reply(socket, 200, error = "NOT_FOUND: $devicePath 不存在")
        if (target.isDirectory) return reply(socket, 200, error = "IS_DIRECTORY: $devicePath 是目录")
        if (target.length() > maxReadBytes) {
            return reply(socket, 200, error = "TOO_LARGE: ${target.length()} 字节，上限 $maxReadBytes")
        }
        val text = runCatching { target.readText() }.getOrElse {
            return reply(socket, 200, error = "READ_FAILED: ${it.message}")
        }
        reply(socket, 200, data = text)
    }

    private fun writeFile(socket: Socket, devicePath: String, target: File, request: JSONObject) {
        if (requireConfirm && !request.optBoolean("confirm", false)) {
            return reply(socket, 200, error = "CONFIRM_REQUIRED: 写入需要 confirm=true")
        }
        // 工作区之外一律拒绝；canonicalPath 会把 ../ 与符号链接解开后再比
        if (!target.path.startsWith(workspace.canonicalPath)) {
            return reply(socket, 200, error = "OUTSIDE_WORKSPACE: 只能写 ${workspace.absolutePath}")
        }
        val content = request.optString("content", "")
        val existed = target.exists()
        target.parentFile?.mkdirs()

        // 先写临时文件再改名，避免读到写了一半的内容
        val temp = File(target.parentFile, ".${target.name}.tmp")
        runCatching { temp.writeText(content) }.getOrElse {
            temp.delete()
            return reply(socket, 200, error = "WRITE_FAILED: ${it.message}")
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            return reply(socket, 200, error = "WRITE_FAILED: 无法覆盖 $devicePath")
        }
        reply(socket, 200, data = if (existed) "updated" else "created")
    }

    /** 读二进制：返回 base64，供插件做图片/附件卡片 */
    private fun readBinary(socket: Socket, devicePath: String, target: File) {
        if (!target.exists()) return reply(socket, 200, error = "NOT_FOUND: $devicePath 不存在")
        if (target.isDirectory) return reply(socket, 200, error = "IS_DIRECTORY: $devicePath 是目录")
        if (target.length() > maxBinaryBytes) {
            return reply(socket, 200, error = "TOO_LARGE: ${target.length()} 字节，上限 $maxBinaryBytes")
        }
        val bytes = runCatching { target.readBytes() }.getOrElse {
            return reply(socket, 200, error = "READ_FAILED: ${it.message}")
        }
        reply(socket, 200, data = Base64.encodeToString(bytes, Base64.NO_WRAP))
    }

    /** 写二进制：从 base64 解码后落盘，栅栏与文本写入一致 */
    private fun writeBinary(socket: Socket, devicePath: String, target: File, request: JSONObject) {
        if (requireConfirm && !request.optBoolean("confirm", false)) {
            return reply(socket, 200, error = "CONFIRM_REQUIRED: 写入需要 confirm=true")
        }
        if (!target.path.startsWith(workspace.canonicalPath)) {
            return reply(socket, 200, error = "OUTSIDE_WORKSPACE: 只能写 ${workspace.absolutePath}")
        }
        val encoded = request.optString("contentBase64", "")
        if (encoded.isEmpty()) return reply(socket, 200, error = "BAD_CONTENT: 缺少 contentBase64")
        val bytes = runCatching { Base64.decode(encoded, Base64.DEFAULT) }.getOrElse {
            return reply(socket, 200, error = "BAD_BASE64: ${it.message}")
        }

        val existed = target.exists()
        target.parentFile?.mkdirs()
        val temp = File(target.parentFile, ".${target.name}.tmp")
        runCatching { temp.writeBytes(bytes) }.getOrElse {
            temp.delete()
            return reply(socket, 200, error = "WRITE_FAILED: ${it.message}")
        }
        if (!temp.renameTo(target)) {
            temp.delete()
            return reply(socket, 200, error = "WRITE_FAILED: 无法覆盖 $devicePath")
        }
        reply(socket, 200, data = if (existed) "updated" else "created")
    }

    /** 列出目录（最多 500 项），返回 JSON 数组字符串 */
    private fun listDir(socket: Socket, devicePath: String, target: File) {
        if (!target.exists()) return reply(socket, 200, error = "NOT_FOUND: $devicePath 不存在")
        if (!target.isDirectory) return reply(socket, 200, error = "NOT_DIRECTORY: $devicePath 不是目录")

        val children = runCatching { target.listFiles() }.getOrNull()?.sortedBy { it.name } ?: emptyList()
        val array = JSONArray()
        for (child in children.take(500)) {
            array.put(JSONObject().apply {
                put("name", child.name)
                put("type", if (child.isDirectory) "dir" else "file")
                put("size", if (child.isDirectory) 0L else child.length())
            })
        }
        reply(socket, 200, data = array.toString())
    }

    /** 文件元信息 */
    private fun statFile(socket: Socket, devicePath: String, target: File) {
        if (!target.exists()) return reply(socket, 200, error = "NOT_FOUND: $devicePath 不存在")
        reply(socket, 200, data = JSONObject().apply {
            put("type", if (target.isDirectory) "dir" else "file")
            put("size", if (target.isDirectory) 0L else target.length())
            put("mtime", target.lastModified())
        }.toString())
    }

    private fun readHeaders(input: InputStream): ByteArray? {
        val buffer = ByteArrayOutputStream()
        var a = -1
        var b = -1
        var c = -1
        while (buffer.size() < 16 * 1024) {
            val byte = input.read()
            if (byte < 0) return null
            buffer.write(byte)
            if (a == 13 && b == 10 && c == 13 && byte == 10) {
                return buffer.toByteArray().copyOf(buffer.size() - 4)
            }
            a = b
            b = c
            c = byte
        }
        return null
    }

    private fun reply(socket: Socket, status: Int, data: String? = null, error: String? = null) {
        val payload = JSONObject()
        payload.put("ok", error == null)
        if (error == null) payload.put("data", data ?: "") else payload.put("error", error)
        val body = payload.toString().toByteArray(StandardCharsets.UTF_8)

        val head = buildString {
            append("HTTP/1.1 ").append(status).append(" OK\r\n")
            append("Content-Type: application/json; charset=utf-8\r\n")
            append("Content-Length: ").append(body.size).append("\r\n")
            append("Access-Control-Allow-Origin: *\r\n")
            append("Access-Control-Allow-Headers: content-type, authorization\r\n")
            append("Access-Control-Allow-Methods: POST, OPTIONS\r\n")
            append("Access-Control-Allow-Private-Network: true\r\n")
            append("Access-Control-Max-Age: 600\r\n")
            append("Connection: close\r\n\r\n")
        }
        runCatching {
            socket.getOutputStream().apply {
                write(head.toByteArray(StandardCharsets.US_ASCII))
                write(body)
                flush()
            }
        }
    }

    companion object {
        private const val TAG = "FloatFsBridge"

        /** Android 11+ 需要「所有文件访问」才能任意读写 /sdcard */
        fun hasAllFilesAccess(): Boolean =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) Environment.isExternalStorageManager() else true

        /** 跳到系统的「所有文件访问」授权页 */
        fun requestAllFilesAccess(context: Context) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
            runCatching {
                context.startActivity(
                    Intent(
                        Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:${context.packageName}"),
                    ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                )
            }.onFailure {
                Log.w(TAG, "无法打开授权页: ${it.message}")
            }
        }
    }
}
