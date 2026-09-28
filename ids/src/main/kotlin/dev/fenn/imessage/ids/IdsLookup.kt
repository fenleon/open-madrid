package dev.fenn.imessage.ids

import dev.fenn.imessage.codec.BpArray
import dev.fenn.imessage.codec.BpDict
import dev.fenn.imessage.codec.BpString
import dev.fenn.imessage.codec.Bplist
import dev.fenn.imessage.codec.BplistFormatException
import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import java.io.ByteArrayInputStream
import java.security.PrivateKey
import java.util.Base64
import java.util.zip.GZIPInputStream

/** Lookup request/response failure (spec §2.1). */
class IdsLookupException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The lookup transport seam (spec §2.1 architecture fact): IDS lookups ride the APNs tunnel,
 * never plain HTTPS. One round trip = a command-96 tunnel request carrying the URL, headers,
 * content type and body; the command-97 reply carries a tunnel-level status and the body.
 * Tests script it; production is [CourierTunnelTransport] over the live courier connection.
 */
interface LookupTransport {

    suspend fun exchange(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): TunnelReply
}

/** The tunnel reply of spec §2.1: the command-97 status field and the response body. */
class TunnelReply(val status: Int, val body: ByteArray)

/**
 * Everything a lookup needs. All header wire names are recorded (C47 closed, spec §2.1) and
 * owned by [IdsLookupClient] — nothing here carries names anymore:
 *
 * - [versionUa] composes the recorded `user-agent` = `com.apple.madrid-lookup <version-ua>`
 *   (§2.1); the `<version-ua>` component is the caller's version string (§1.4's register
 *   user-agent pattern).
 * - [subService] rides as `x-id-sub-service` only when set — §2.1: "only when the lookup
 *   topic differs from the main topic"; the caller decides applicability.
 * - [requiredForMessage]/[resultExpected] are the opt-in flags `x-required-for-message` /
 *   `x-result-expected`, both true "in most calls" (§2.1), so they default to true.
 */
data class LookupConfig(
    val selfUri: String,
    val pushToken: ByteArray,
    val protocolVersion: String,
    val versionUa: String,
    val signingKey: PrivateKey,
    val certificateDer: ByteArray,
    val subService: String? = null,
    val requiredForMessage: Boolean = true,
    val resultExpected: Boolean = true,
)

/**
 * One device's public identity. The six per-identity wire keys are recorded (C48 closed,
 * spec §2.1); only the two token-timing fields have typed accessors — the rest
 * (`client-data`, `kt-loggable-data`, `push-token`, `session-token`) stay in [raw] for the
 * component that needs them.
 */
data class IdsIdentity(
    val expiresSeconds: Long?,
    val refreshSeconds: Long?,
    val raw: Map<String, Any?>,
)

/**
 * One handle's lookup result. [status] is the per-handle `status` wire key (C48, recorded) —
 * kept for storage fidelity only: C55 (spec §2.1/§7 item 19) supersedes routing on it, both
 * reference clients read lookup error statuses from the top-level `status` only. Absent
 * per-handle status parses as 0 (neither reference client consults the value).
 */
data class IdsLookupResult(
    val status: Int,
    val identities: List<IdsIdentity>,
    val raw: Map<String, Any?>,
)

/**
 * A lookup response (spec §2.1, C48 closed): top-level `status` — where 5206/6005 and the
 * unhandled 5040/5041 are read from (C55) — plus `results`, the map keyed by the plain uri
 * string. Per-handle `kt-account-key` / `sender-correlation-identifier` ride in each
 * result's [IdsLookupResult.raw].
 */
data class IdsLookupResponse(
    val status: Int,
    val results: Map<String, IdsLookupResult>,
)

/**
 * IDS lookup client per spec §2.1: the lookup body — a plist with a `uris` array of PLAIN
 * handle strings (bare `tel:`/`mailto:` strings, not the register-style single-key dicts) —
 * signed with the §1.4 construction, carried over the tunnel [transport] to the bag's
 * `id-query` URL.
 *
 * Batch size is the caller's decision: §2.1 records 18 handles vs 20 URIs and leaves the cap
 * open (TODO(capture) C13), so nothing is hardcoded here. The 5206 "response too large"
 * split-in-half retry of §2.1 belongs around this call, in the caller that owns the batch.
 *
 * [plistParser] is the plist seam (see [IdsBagFetcher]); the default is [Plist.parse].
 */
class IdsLookupClient(
    private val transport: LookupTransport,
    private val bag: Bag,
    private val config: LookupConfig,
    private val plistParser: (ByteArray) -> Any? = { Plist.parse(it) },
) {

    suspend fun lookup(uris: List<String>): IdsLookupResponse {
        val url = bag.url(BAG_KEY)
        val body = encodeBody(uris)
        val nonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS)
        val signature = IdsSigning.sign(config.signingKey, nonce, signingFields(body))

        // §1.4 states base64 for the signature only; the nonce and the certificate are sent the
        // same way because no other encoding is recorded (§1.4 extraction, C47-closed names).
        val headers = LinkedHashMap<String, String>()
        headers["x-id-nonce"] = base64(nonce)
        headers["x-id-cert"] = base64(config.certificateDer)
        headers["x-id-sig"] = base64(signature)
        headers[HEADER_PUSH_TOKEN] = base64(config.pushToken)
        headers[HEADER_SELF_URI] = config.selfUri
        headers[HEADER_PROTOCOL_VERSION] = config.protocolVersion
        headers[HEADER_USER_AGENT] = "$USER_AGENT_PREFIX ${config.versionUa}"
        headers[HEADER_REQUIRED_FOR_MESSAGE] = config.requiredForMessage.toString()
        headers[HEADER_RESULT_EXPECTED] = config.resultExpected.toString()
        config.subService?.let { headers[HEADER_SUB_SERVICE] = it }

        val reply = transport.exchange(url, headers, body, PLIST_CONTENT_TYPE)
        if (reply.status != TunnelStatus.OK) {
            throw IdsLookupException("lookup tunnel reply status ${reply.status} (expected 0)")
        }
        return parseResponse(gunzipIfNeeded(reply.body))
    }

    /**
     * The signed field tuple of §1.4: (bag key string, query string — empty for a lookup,
     * request body, raw push token). The body is the exact bytes sent.
     */
    private fun signingFields(body: ByteArray): List<ByteArray> = listOf(
        BAG_KEY.toByteArray(Charsets.UTF_8),
        EMPTY_QUERY,
        body,
        config.pushToken,
    )

    /**
     * Encoding is one swap point because it is unrecorded: §1.4 has the register body as XML,
     * §2.1 says only "a plist", so the lookup body goes out as the binary plist of §4.1
     * (TODO(capture) C12) — change this line to move to XML.
     */
    private fun encodeBody(uris: List<String>): ByteArray =
        Bplist.encode(BpDict(mapOf(BpString("uris") to BpArray(uris.map { BpString(it) }))))

    private fun parseResponse(bytes: ByteArray): IdsLookupResponse {
        val parsed = try {
            plistParser(bytes)
        } catch (e: PlistFormatException) {
            throw IdsLookupException("lookup response is not a plist: ${e.message}", e)
        }
        val dict = stringKeyedDictOrNull(parsed)
            ?: throw IdsLookupException("lookup response is ${typeName(parsed)}, expected a dict")
        val status = when (val value = dict[TOP_LEVEL_STATUS]) {
            is Long -> value.toInt()
            is Int -> value
            else -> throw IdsLookupException(
                "lookup response has no top-level integer 'status' (${typeName(value)}) — " +
                    "spec §2.1 records it as the C55 error-status location",
            )
        }
        val resultsDict = stringKeyedDictOrNull(dict[TOP_LEVEL_RESULTS])
            ?: throw IdsLookupException(
                "lookup response 'results' is ${typeName(dict[TOP_LEVEL_RESULTS])}, expected a handle-keyed dict",
            )
        val results = LinkedHashMap<String, IdsLookupResult>(resultsDict.size)
        for ((handle, value) in resultsDict) {
            val result = stringKeyedDictOrNull(value)
                ?: throw IdsLookupException("lookup result for '$handle' is ${typeName(value)}, expected a dict")
            results[handle] = parseResult(result, handle)
        }
        return IdsLookupResponse(status, results)
    }

    private fun parseResult(raw: Map<String, Any?>, handle: String): IdsLookupResult {
        // The per-handle `status` key is recorded (C48) but read by no reference client (C55):
        // parsed leniently for storage fidelity, never routed on.
        val status = when (val value = raw["status"]) {
            is Long -> value.toInt()
            is Int -> value
            else -> 0
        }
        val identities = when (val value = raw["identities"]) {
            null -> emptyList() // registered nowhere: §2.2's zero-identity case
            is List<*> -> value.mapIndexed { i, identity -> parseIdentity(identity, handle, i) }
            else -> throw IdsLookupException("'identities' for '$handle' is ${typeName(value)}, expected an array")
        }
        return IdsLookupResult(status, identities, raw)
    }

    private fun parseIdentity(raw: Any?, handle: String, index: Int): IdsIdentity {
        val dict = stringKeyedDictOrNull(raw)
            ?: throw IdsLookupException("identity $index of '$handle' is ${typeName(raw)}, expected a dict")
        return IdsIdentity(
            expiresSeconds = longOrNull(dict[SESSION_TOKEN_EXPIRES]),
            refreshSeconds = longOrNull(dict[SESSION_TOKEN_REFRESH]),
            raw = dict,
        )
    }

    private fun longOrNull(value: Any?): Long? = when (value) {
        is Long -> value
        is Int -> value.toLong()
        else -> null
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    companion object {
        /** Bag key for the lookup endpoint (spec §1.2/§2.1). */
        const val BAG_KEY = "id-query"

        /** The plist content type of §1.4 (recorded for register; the lookup's is not, C12). */
        const val PLIST_CONTENT_TYPE = "application/x-apple-plist"

        // C47-closed header wire names (spec §2.1).
        const val HEADER_SELF_URI = "x-id-self-uri"
        const val HEADER_PUSH_TOKEN = "x-push-token"
        const val HEADER_PROTOCOL_VERSION = "x-protocol-version"
        const val HEADER_USER_AGENT = "user-agent"
        const val HEADER_SUB_SERVICE = "x-id-sub-service"
        const val HEADER_REQUIRED_FOR_MESSAGE = "x-required-for-message"
        const val HEADER_RESULT_EXPECTED = "x-result-expected"

        /** §2.1: `user-agent` = `com.apple.madrid-lookup <version-ua>`. */
        const val USER_AGENT_PREFIX = "com.apple.madrid-lookup"

        private const val TOP_LEVEL_STATUS = "status"
        private const val TOP_LEVEL_RESULTS = "results"
        private const val SESSION_TOKEN_EXPIRES = "session-token-expires-seconds"
        private const val SESSION_TOKEN_REFRESH = "session-token-refresh-seconds"
        private val EMPTY_QUERY = ByteArray(0)
    }
}

/** The command-97 tunnel-level status values the spec supports (§2.1; 0 = ok, APNs convention). */
object TunnelStatus {
    const val OK = 0
}

/**
 * §2.1 calls the response "a gzipped plist". The tunnel reply body's own magic, not any
 * header, decides whether to unwrap.
 */
fun gunzipIfNeeded(body: ByteArray): ByteArray =
    if (body.size >= 2 && body[0] == 0x1f.toByte() && body[1] == 0x8b.toByte()) {
        GZIPInputStream(ByteArrayInputStream(body)).use { it.readBytes() }
    } else {
        body
    }
