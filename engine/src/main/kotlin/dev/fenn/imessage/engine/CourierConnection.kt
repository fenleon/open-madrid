package dev.fenn.imessage.engine

import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierFrame
import java.io.Closeable
import java.io.IOException
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * The coroutine lifecycle over [CourierClient]: TLS socket construction (the pinned trust
 * managers plus the optional Albert client certificate as [KeyManager]s — the handshake
 * client-certificate question is C18-open), one long-lived [CourierClient.run] session, and
 * a [state] flow for the app shell's UI/FGS. No Android service code — the FGS wiring is the
 * app shell's; this class only owns the connection coroutine.
 *
 * Trigger wiring lives with the host: the courier handler forwards frames to the engine's
 * frame pipeline ([CourierFrame]s — tunnel replies feed [dev.fenn.imessage.ids.CourierTunnelTransport.onFrame],
 * send frames on the private-IDS topic feed [dev.fenn.imessage.ids.PrivateIdsPush]), and
 * [dev.fenn.imessage.registration.IdsRenewal.onPrivateIdsCommand] consumes the command counts.
 */
class CourierConnection(
    private val courierConfig: CourierClient.Config,
    trustManagers: Array<TrustManager>,
    keyManagers: Array<KeyManager> = emptyArray(),
) : Closeable {

    enum class State { DISCONNECTED, CONNECTING, CONNECTED }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val sslContext = SSLContext.getInstance("TLS").apply { init(keyManagers, trustManagers, null) }
    private val client = CourierClient(courierConfig) { tcpSocket, sniHost ->
        sslContext.socketFactory.createSocket(tcpSocket, sniHost, tcpSocket.port, true) as SSLSocket
    }
    private var job: Job? = null
    private val _state = MutableStateFlow(State.DISCONNECTED)
    val state: StateFlow<State> = _state.asStateFlow()

    /**
     * Starts (or restarts) the connect/read/keepalive/reconnect loop; inbound frames go to
     * [handler.onFrame], [handler.onConnected] fires per established connection. Idempotent
     * while running.
     */
    fun start(handler: CourierClient.Handler) {
        if (job?.isActive == true) return
        _state.value = State.CONNECTING
        job = scope.launch {
            try {
                client.run(ForwardingHandler(handler))
            } finally {
                _state.value = State.DISCONNECTED
            }
        }
    }

    /** Cancels the session (closes the socket with it). Suspend: waits for the loop to exit. */
    suspend fun stop() {
        job?.let { job -> job.cancel(); job.join() }
        _state.value = State.DISCONNECTED
    }

    fun sendFrame(frame: ByteArray) = client.sendFrame(frame)

    override fun close() = scope.cancel()

    private inner class ForwardingHandler(
        private val delegate: CourierClient.Handler,
    ) : CourierClient.Handler {
        override fun onConnected() {
            _state.value = State.CONNECTED
            delegate.onConnected()
        }

        override fun onFrame(frame: CourierFrame.Frame) = delegate.onFrame(frame)
    }
}
