package dev.fenn.imessage.engine

import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import kotlin.concurrent.thread

/**
 * Minimal offline HTTP server for engine tests (the JDK's com.sun.net.httpserver is not on
 * the unit-test compile classpath — android.jar bootclasspath). One request per connection
 * (responds `Connection: close`); handler runs on a daemon accept loop.
 */
class LocalHttpServer(private val handler: (Request) -> Response) {

    class Request(val method: String, val path: String, val headers: Map<String, String>, val body: ByteArray)

    class Response(val status: Int, val headers: Map<String, String> = emptyMap(), val body: ByteArray = ByteArray(0))

    private var serverSocket: ServerSocket? = null

    fun start() {
        check(serverSocket == null)
        val socket = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        serverSocket = socket
        thread(isDaemon = true, name = "LocalHttpServer") {
            while (true) {
                val client = try {
                    socket.accept()
                } catch (_: Exception) {
                    return@thread
                }
                thread(isDaemon = true) { serve(client) }
            }
        }
    }

    val port: Int get() = serverSocket!!.localPort

    fun stop() {
        serverSocket?.close()
    }

    private fun serve(socket: Socket) {
        try {
            socket.use { s ->
                val input = s.getInputStream()
                val requestLine = input.readLine() ?: return
                val headers = HashMap<String, String>()
                while (true) {
                    val line = input.readLine()
                    if (line.isNullOrEmpty()) break
                    val colon = line.indexOf(':')
                    if (colon > 0) headers[line.substring(0, colon).trim().lowercase()] = line.substring(colon + 1).trim()
                }
                val contentLength = headers["content-length"]?.toIntOrNull() ?: 0
                val body = ByteArray(contentLength)
                var read = 0
                while (read < contentLength) {
                    val n = input.read(body, read, contentLength - read)
                    if (n < 0) break
                    read += n
                }
                val response = handler(
                    Request(
                        requestLine.substringBefore(' '),
                        requestLine.substringAfter(' ').substringBefore(' '),
                        headers,
                        body,
                    ),
                )
                val out = s.getOutputStream()
                val head = buildString {
                    append("HTTP/1.1 ").append(response.status).append(" OK\r\n")
                    response.headers.forEach { (name, value) -> append(name).append(": ").append(value).append("\r\n") }
                    append("Content-Length: ").append(response.body.size).append("\r\n")
                    append("Connection: close\r\n\r\n")
                }
                out.write(head.toByteArray(Charsets.ISO_8859_1))
                out.write(response.body)
                out.flush()
            }
        } catch (_: Exception) {
            // client vanished mid-request — nothing to do for a test double
        }
    }

    private fun InputStream.readLine(): String? {
        val out = StringBuilder()
        while (true) {
            val c = read()
            if (c < 0) return if (out.isEmpty()) null else out.toString()
            if (c == '\n'.code) return out.toString().trimEnd('\r')
            out.append(c.toChar())
        }
    }
}
