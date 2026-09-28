package dev.fenn.imessage.courier

import java.io.Closeable
import java.io.IOException
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.SSLSocket
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * APNs courier transport per spec §3: TLS to "<random 1..count>-<hostname>" with SNI set
 * to the bare hostname, legacy frame format, keepalive pacing, reconnect with backoff.
 *
 * Command construction lives in [CourierCommands] / [CourierConnect] (spec §3.3, C45 closed
 * in rev 12). Keepalive/reconnect pacing are our client-policy constants (both source
 * policies are recorded in spec §3.4; C21 open).
 *
 * TLS (§3.1 [CAP-COURIERTLS]): the courier chain anchors at the publicly-trusted
 * `AAA Certificate Services` root — unlike the IDS endpoints, which anchor at Apple roots —
 * so [tlsFactory] must pin that root (root only; the leaf rotates every ~90 days). Port
 * note: the originating repo's embedded-root trust component was not ported into this
 * module, so no default factory is provided — the caller supplies the pinned factory.
 * Whether the handshake presents the Albert client certificate is C18-open — no client
 * certificate is configured here.
 */
class CourierClient(
    private val config: Config,
    private val tlsFactory: (tcpSocket: Socket, sniHost: String) -> SSLSocket,
) : Closeable {

    data class Config(
        /** Bag `APNSCourierHostname` (spec §3.1, [CAP-APNSBAG]: courier.push.apple.com). */
        val hostname: String,
        /** Bag `APNSCourierHostcount` (spec §3.1, [CAP-APNSBAG]: 50). */
        val hostCount: Int = 50,
        val port: Int = 5223,
        val keepaliveSecs: Long = 60,
        val pongTimeoutSecs: Long = 15,
        val backoffCapSecs: Long = 30,
    )

    interface Handler {
        fun onFrame(frame: CourierFrame.Frame) {}
        fun onConnected() {}
    }

    private val random = SecureRandom()
    private val backoffAttempt = AtomicLong(0)
    private var socket: SSLSocket? = null
    private val writeLock = Any()

    /** Random message id for send messages: 1..2^31−1 (spec §3.3). */
    // The two-arg origin-bound nextInt is a desktop-JVM API ART lacks (NoSuchMethodError
    // on-device, found by the service smoke) — use the classic bound form everywhere.
    fun newMessageId(): Int = random.nextInt(Int.MAX_VALUE - 1) + 1

    fun sendFrame(frame: ByteArray) {
        val s = socket ?: throw IOException("not connected")
        synchronized(writeLock) {
            s.getOutputStream().apply { write(frame); flush() }
        }
    }

    /**
     * Runs the connect/read/keepalive/reconnect loop until cancelled. Each connection
     * calls [handler.onConnected], then every inbound frame goes to [handler.onFrame].
     */
    suspend fun run(handler: Handler) {
        while (coroutineContext.isActive) {
            val tcpHost = courierHost(config.hostname, config.hostCount, random)
            try {
                socket = withContext(Dispatchers.IO) {
                    val tcp = Socket()
                    tcp.connect(java.net.InetSocketAddress(tcpHost, config.port), CONNECT_TIMEOUT_MS)
                    val ssl = tlsFactory(tcp, config.hostname)
                    tcp.soTimeout = CONNECT_TIMEOUT_MS
                    try {
                        ssl.startHandshake()
                    } finally {
                        tcp.soTimeout = 0 // idle connections are healthy — only keepalive drops
                    }
                    ssl
                }
                backoffAttempt.set(0)
                handler.onConnected()
                val connection = socket!!
                coroutineScope {
                    val reader = launch(Dispatchers.IO) { readLoop(connection, handler) }
                    launch(Dispatchers.IO) { keepaliveLoop(connection) }
                    reader.join()
                    closeSocket() // ends the keepalive ticker with the reader
                }
            } catch (e: CancellationException) {
                closeSocket()
                throw e
            } catch (e: Exception) {
                // reconnect loop: backoff applied below (spec §3.4, client policy)
            } finally {
                closeSocket()
            }
            val attempt = backoffAttempt.getAndIncrement()
            delay(backoffDelayMs(attempt, config.backoffCapSecs * 1000))
        }
    }

    private fun readLoop(connection: SSLSocket, handler: Handler) {
        val input = connection.getInputStream()
        while (true) {
            val frame = CourierFrame.decode(input) ?: return // clean EOF
            if (frame.command == CourierFrame.KEEPALIVE_ACK) lastPongMillis = System.currentTimeMillis()
            handler.onFrame(frame)
        }
    }

    @Volatile
    private var lastPongMillis: Long = 0

    private fun keepaliveLoop(connection: SSLSocket) {
        val intervalMs = config.keepaliveSecs * 1000
        val timeoutMs = config.pongTimeoutSecs * 1000
        lastPongMillis = System.currentTimeMillis()
        while (!connection.isClosed) {
            try {
                sendFrame(CourierFrame.encode(CourierFrame.KEEPALIVE))
            } catch (e: IOException) {
                return // reader will notice too; reconnect loop takes over
            }
            var slept = 0L
            while (slept < intervalMs && !connection.isClosed) {
                Thread.sleep(minOf(500L, intervalMs - slept))
                slept += 500L
            }
            if (System.currentTimeMillis() - lastPongMillis > intervalMs + timeoutMs) {
                closeSocket() // silent past the pong window — drop and let the loop reconnect
                return
            }
        }
    }

    override fun close() = closeSocket()

    private fun closeSocket() {
        try {
            socket?.close()
        } catch (e: IOException) {
            // already closed / half-closed — nothing to do
        }
        socket = null
    }

    companion object {
        /** Connect to "<random 1..count>-<hostname>", SNI on the bare hostname (spec §3.1). */
        fun courierHost(hostname: String, hostCount: Int, random: SecureRandom): String =
            "${random.nextInt(hostCount) + 1}-$hostname"

        /** Exponential backoff 1 s, 2 s, 4 s … capped (spec §3.4 client policy; C21 open). */
        fun backoffDelayMs(attempt: Long, capMs: Long): Long =
            (1000L shl minOf(attempt, 20).toInt()).coerceAtMost(capMs)

        private const val CONNECT_TIMEOUT_MS = 10_000
    }
}
