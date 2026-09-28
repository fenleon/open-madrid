package dev.fenn.imessage.ids

import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The APNs tunnel transport adapter for IDS lookups (spec §2.1 architecture fact): sends each
 * lookup as a command-96 tunnel request over the live courier connection and completes when
 * the command-97 response with the same 16-byte request UUID arrives — the correlation the
 * spec records — with the §2.1 1-minute timeout around the wait.
 *
 * Wiring: [sendFrame] resolves the connected courier client (`CourierClient.sendFrame` over
 * [CourierFrame.encode]); [onFrame] is called from the courier handler for every inbound
 * frame, so a session composes it into its `CourierClient.Handler`. Responses for unknown or
 * expired requests are dropped — the waiting caller has already timed out.
 */
class CourierTunnelTransport(
    private val fieldIds: CourierCommands.TunnelFieldIds,
    private val sendFrame: (CourierFrame.Frame) -> Unit,
    private val timeoutMs: Long = TIMEOUT_MS,
    private val random: SecureRandom = SecureRandom(),
    private val logEvent: (String) -> Unit = {},
) : LookupTransport {

    private val pending = ConcurrentHashMap<String, CompletableDeferred<CourierFrame.Frame>>()

    /** Feeds courier frames in; only command-97 responses are consumed. */
    fun onFrame(frame: CourierFrame.Frame) {
        if (frame.command != CourierFrame.TUNNEL_RESPONSE) return
        val response = runCatching { CourierCommands.parseTunnelResponse(frame, fieldIds) }
            .getOrElse { e ->
                logEvent("malformed tunnel response dropped: ${e.message}")
                return
            }
        pending.remove(response.requestUuid.hex())?.complete(frame)
            ?: logEvent("tunnel response with no waiting request dropped")
    }

    override suspend fun exchange(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): TunnelReply {
        val requestUuid = ByteArray(CourierCommands.TUNNEL_REQUEST_UUID_BYTES).also(random::nextBytes)
        val deferred = CompletableDeferred<CourierFrame.Frame>()
        pending[requestUuid.hex()] = deferred // registered before the send — no reply can race it
        try {
            sendFrame(
                CourierCommands.tunnelRequestFrame(url, headers, contentType, body, requestUuid, fieldIds),
            )
            val frame = withTimeoutOrNull(timeoutMs) { deferred.await() }
                ?: throw IdsLookupException(
                    "tunnel request timed out after $timeoutMs ms (§2.1's 1-minute timeout)",
                )
            val response = CourierCommands.parseTunnelResponse(frame, fieldIds)
            if (!response.requestUuid.contentEquals(requestUuid)) {
                throw IdsLookupException("tunnel response uuid does not match the request")
            }
            if (response.status != TunnelStatus.OK) {
                throw IdsLookupException("tunnel response status ${response.status} (expected 0)")
            }
            return TunnelReply(response.status, response.body)
        } finally {
            pending.remove(requestUuid.hex())
        }
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    companion object {
        /** Spec §2.1: "a 1-minute timeout applies". */
        const val TIMEOUT_MS = 60_000L
    }
}
