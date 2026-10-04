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
 * to the bare hostname, legacy or packed frame format by the negotiated ALPN (§3.2, C19 —
 * `apns-pack-v1` selects the packed codec; legacy stays the default path), keepalive pacing,
 * reconnect with backoff.
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
 * Client certificate: on the packed `apns-pack-v1` path no TLS client certificate is
 * demanded (rev 26 — the push certificate rides only in the connect frame); the C18
 * post-handshake client-cert alert belongs to the no-ALPN legacy path. No client
 * certificate is configured here either way.
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
        /** The negotiated codec; build and send the connect through it (§3.2, C19). */
        fun onConnected(codec: Codec) {}

        fun onFrame(frame: CourierFrame.Frame) {}

        /** Packed-format frame (§3.2, C19) — delivered instead of [onFrame] on a packed connection. */
        fun onPackedFrame(frame: CourierPacked.Frame) {}
    }

    /** The wire codec chosen by the negotiated ALPN (spec §3.2, C19). */
    interface Codec {
        fun sendConnect(token: ByteArray?, certDer: ByteArray, nonce: ByteArray, signature: ByteArray)

        fun sendSetState()

        fun sendFilter(token: ByteArray, enabledTopics: List<String>)

        fun sendPing()
    }

    private inner class PackedCodec : Codec {
        override fun sendConnect(token: ByteArray?, certDer: ByteArray, nonce: ByteArray, signature: ByteArray) {
            sendFrame(CourierPacked.connectFrame(token, certDer, nonce, signature))
        }

        override fun sendSetState() {
            sendFrame(CourierPacked.setStateFrame())
        }

        override fun sendFilter(token: ByteArray, enabledTopics: List<String>) {
            sendFrame(CourierPacked.filterFrame(token, enabledTopics))
        }

        override fun sendPing() {
            sendFrame(CourierPacked.ping())
        }
    }

    private inner class LegacyCodec : Codec {
        override fun sendConnect(token: ByteArray?, certDer: ByteArray, nonce: ByteArray, signature: ByteArray) {
            val frame = CourierConnect.connectFrame(
                deviceToken = token ?: ByteArray(0),
                pushCertificateDer = certDer,
                nonce = nonce,
                signature = signature,
            )
            sendFrame(CourierFrame.encode(frame.command, frame.fields.map { it.id to it.value }))
        }

        override fun sendSetState() {
            val frame = CourierCommands.setStateFrame(CourierCommands.CONNECT_STATE)
            sendFrame(CourierFrame.encode(frame.command, frame.fields.map { it.id to it.value }))
        }

        override fun sendFilter(token: ByteArray, enabledTopics: List<String>) {
            val frame = CourierCommands.filterFrame(
                token,
                enabled = enabledTopics.map(CourierCommands::topicHash),
                shape = CourierCommands.FilterShape.TOPIC_LIST,
            )
            sendFrame(CourierFrame.encode(frame.command, frame.fields.map { it.id to it.value }))
        }

        override fun sendPing() {
            sendFrame(CourierFrame.encode(CourierFrame.KEEPALIVE))
        }
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
     * Runs the connect/read/keepalive/reconnect loop until cancelled. Each connection calls
     * [handler.onConnected] with the ALPN-negotiated codec, then every inbound frame goes to
     * [handler.onFrame] (legacy framing) or [handler.onPackedFrame] (packed framing, C19).
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
                    // Offer the packed-format ALPN the courier speaks (spec §3.2, C19, rev 26):
                    // the live server ignores the offer and answers `apns-pack-v1:<enc>:<dec>`
                    // (observed 4096:4096 on every host) — OpenJDK rejects a selection outside
                    // the offer, so the exact suffixed form must be offered alongside the bare
                    // names; the legacy path stays the default when no pack protocol is selected.
                    ssl.sslParameters = (ssl.sslParameters ?: javax.net.ssl.SSLParameters()).apply {
                        applicationProtocols = arrayOf("apns-pack-v1:4096:4096", "apns-pack-v1", "apns-security-v3")
                    }
                    try {
                        ssl.startHandshake()
                    } finally {
                        tcp.soTimeout = 0 // idle connections are healthy — only keepalive drops
                    }
                    ssl
                }
                backoffAttempt.set(0)
                val codec = codecFor(socket!!)
                handler.onConnected(codec)
                val connection = socket!!
                coroutineScope {
                    val reader = launch(Dispatchers.IO) { readLoop(codec, connection, handler) }
                    launch(Dispatchers.IO) { keepaliveLoop(codec, connection) }
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

    /** The ALPN-negotiated codec: `apns-pack-v1*` speaks the packed format (§3.2, C19), else legacy. */
    private fun codecFor(ssl: SSLSocket): Codec =
        if (ssl.applicationProtocol?.startsWith("apns-pack-v1") == true) PackedCodec() else LegacyCodec()

    private fun readLoop(codec: Codec, connection: SSLSocket, handler: Handler) {
        val input = connection.getInputStream()
        if (codec is PackedCodec) {
            val packed = CourierPacked()
            while (true) {
                val frame = packed.decode(input) ?: return // clean EOF
                if (frame.command == CourierFrame.KEEPALIVE_ACK) lastPongMillis = System.currentTimeMillis()
                handler.onPackedFrame(frame)
            }
        }
        while (true) {
            val frame = CourierFrame.decode(input) ?: return // clean EOF
            if (frame.command == CourierFrame.KEEPALIVE_ACK) lastPongMillis = System.currentTimeMillis()
            handler.onFrame(frame)
        }
    }

    @Volatile
    private var lastPongMillis: Long = 0

    private fun keepaliveLoop(codec: Codec, connection: SSLSocket) {
        val intervalMs = config.keepaliveSecs * 1000
        val timeoutMs = config.pongTimeoutSecs * 1000
        lastPongMillis = System.currentTimeMillis()
        while (!connection.isClosed) {
            try {
                codec.sendPing()
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
