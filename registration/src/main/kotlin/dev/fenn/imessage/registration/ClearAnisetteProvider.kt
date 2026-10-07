package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/** Provisioning or header derivation failed (wire shape per anisette_clearadi.rs, flow ref). */
class ClearAdiProvisioningException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Persistence seam for the provisioned state (the `AnisetteState` of the reference —
 * reference/apple-private-apis/omnisette/src/anisette_clearadi.rs, MPL-2.0 — persisted there
 * as a plist file; here a JSON string, because open-madrid is a pure JVM library with no
 * Context to derive a files dir from). The caller owns the storage location.
 */
interface ClearAdiStateStore {
    /** Persist the JSON (overwrite); called after every successful provisioning. */
    fun save(json: String)

    /** The last saved JSON, or null when nothing was stored yet. */
    fun load(): String?
}

/**
 * The per-request identity inputs the reference's `ClearADIClient.login_info` carries
 * (anisette_clearadi.rs §ClearADIClient/build_apple_request).
 */
data class ClearAdiLoginInfo(
    /** `User-Agent` — the reference's `akd_user_agent`. */
    val akdUserAgent: String,
    /** `X-Mme-Client-Info` — also decides the flavor: "iPhone OS" ⇒ IOS, else Mac. */
    val mmeClientInfo: String,
    /** Extra hardware headers appended verbatim after the fixed set (reference: `hardware_headers`). */
    val hardwareHeaders: Map<String, String> = emptyMap(),
)

/**
 * The provisioning outcome: `finish()`'s raw ProvisionedData plus the response's routing info.
 * The ProvisionedData→{client_secret, mid, metadata} mapping is TODO(live-capture) (one
 * OpenBubbles provisioning run under gdb) — the raw 0x78 bytes are carried as-is and the
 * mapping lives nowhere until then.
 */
data class ClearAdiProvisionResult(
    val provisionedData: ProvisionedData,
    val rinfo: String,
)

/** State JSON of [ClearAdiProvisionResult] (hex ProvisionedData + rinfo; mapping TODO). */
fun resultToJson(result: ClearAdiProvisionResult): String = buildJsonObject {
    put("provisioned_data", result.provisionedData.raw.joinToString("") { "%02x".format(it) })
    put("rinfo", result.rinfo)
}.toString()

fun resultFromJson(json: String): ClearAdiProvisionResult {
    val o = Json.parseToJsonElement(json).jsonObject
    val hexData = o["provisioned_data"]!!.jsonPrimitive.content
    require(hexData.length >= 0x78 * 2) { "stored provisioned_data shorter than 0x78 bytes" }
    val raw = ByteArray(hexData.length / 2) { i ->
        ((Character.digit(hexData[i * 2], 16) shl 4) or Character.digit(hexData[i * 2 + 1], 16)).toByte()
    }
    return ClearAdiProvisionResult(ProvisionedData(raw), o["rinfo"]!!.jsonPrimitive.content)
}

/**
 * The header factory over a provisioned machine: the real OTP derivation
 * ([ClearAdiOtp.anisetteOtp]) behind the repo's [AnisetteOtp] seam, plus the anisette header
 * map of the reference's `AnisetteData::get_headers` (anisette_clearadi.rs, transcribed 1:1:
 * client time ISO-8601 with a trailing `Z`, fixed UTC/en_US, rinfo from the state, the UUID
 * form of the 16-byte keychain identifier as `X-Mme-Device-Id`).
 *
 * Takes (metadata, mid, flavor) directly — the ProvisionedData→fields mapping is
 * TODO(live-capture), so the caller wires them once the capture names the bytes.
 */
class ClearAdiAnisette(
    val metadata: ByteArray,
    val mid: ByteArray,
    val flavor: Int,
    val rinfo: String,
    private val keychainIdentifier: ByteArray,
    /** `X-Mme-Client-Info` — also the flavor decider of the reference. */
    val clientInfo: String = "",
    private val clock: () -> Long = { System.currentTimeMillis() },
) : AnisetteOtp {

    /** The real derivation — the one-time identifier input is unused (the OTP is time-windowed). */
    override fun otp(input: AnisetteOtpInput): ByteArray =
        ClearAdiOtp.anisetteOtp(flavor, metadata, mid, clock() / 1000)

    /** The header map, in the reference's get_headers order. */
    fun headers(): Map<String, String> {
        val otpBytes = otp(AnisetteOtpInput(mid, ByteArray(0)))
        if (otpBytes.isEmpty()) throw AnisetteException("OTP derivation returned no bytes for X-Apple-I-MD")
        val out = LinkedHashMap<String, String>()
        out["X-Apple-I-Client-Time"] = iso8601Z(clock())
        out["X-Apple-I-TimeZone"] = "UTC"
        out["X-Apple-Locale"] = "en_US"
        out["X-Apple-I-MD-RINFO"] = rinfo
        out["X-Mme-Device-Id"] = uuid(keychainIdentifier)
        out["X-Apple-I-MD"] = Base64.getEncoder().encodeToString(otpBytes)
        out["X-Apple-I-MD-M"] = Base64.getEncoder().encodeToString(mid)
        out["X-Mme-Client-Info"] = clientInfo
        return out
    }

    companion object {
        private fun uuid(bytes: ByteArray): String {
            require(bytes.size == 16) { "keychain identifier must be 16 bytes" }
            val bb = java.nio.ByteBuffer.wrap(bytes)
            return UUID(bb.long, bb.long).toString()
        }
    }
}

/** ISO-8601 with the trailing `Z` the reference's get_headers produces (`%+`, +00:00 → Z). */
internal fun iso8601Z(epochMs: Long): String =
    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
        .withZone(java.time.ZoneOffset.UTC)
        .format(java.time.Instant.ofEpochMilli(epochMs))

/** ISO-8601 with the `+00:00` offset the reference's build_apple_request produces (`%+`). */
internal fun iso8601Offset(epochMs: Long): String =
    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'+00:00'")
        .withZone(java.time.ZoneOffset.UTC)
        .format(java.time.Instant.ofEpochMilli(epochMs))

/**
 * The persisted provisioning result (reference `ProvisionedAnisette`): the machine tokens the
 * anisette headers derive from plus the server-assigned routing info. Serialized as a JSON
 * object of base64/hex/string fields — the reference serializes a plist with `Data` fields;
 * the JSON key names mirror its serde names.
 */
data class ProvisionedAnisette(
    val clientSecret: ByteArray,
    val mid: ByteArray,
    val metadata: ByteArray,
    val rinfo: String,
    /** 0 = Mac, 1 = IOS (ClearAdiOtp's flavor convention; the reference's ProvisionedFlavor). */
    val flavor: Int,
) {
    fun toJson(): String = buildJsonObject {
        put("client_secret", Base64.getEncoder().encodeToString(clientSecret))
        put("mid", Base64.getEncoder().encodeToString(mid))
        put("metadata", Base64.getEncoder().encodeToString(metadata))
        put("rinfo", rinfo)
        put("flavor", flavor)
    }.toString()

    companion object {
        fun fromJson(json: String): ProvisionedAnisette {
            val o = Json.parseToJsonElement(json).jsonObject
            fun b64(key: String) = Base64.getDecoder().decode(o[key]!!.jsonPrimitive.content)
            return ProvisionedAnisette(
                clientSecret = b64("client_secret"),
                mid = b64("mid"),
                metadata = b64("metadata"),
                rinfo = o["rinfo"]!!.jsonPrimitive.content,
                flavor = o["flavor"]!!.jsonPrimitive.content.toInt(),
            )
        }
    }
}

/**
 * The wire-level ClearADI anisette provider — the Kotlin counterpart of the reference
 * `ClearADIClient::provision` (reference/apple-private-apis/omnisette/src/anisette_clearadi.rs,
 * MPL-2.0; the file is the flow reference, the .so is the wire ground truth):
 *
 * 1. `GET https://gsa.apple.com/grandslam/GsService2/lookup` → XML plist →
 *    `urls.{midStartProvisioning, midFinishProvisioning}`
 * 2. `POST <start>` with body `{"header":{}, "request":{}}` (XML plist,
 *    `Content-Type: application/x-www-form-urlencoded` — "not a bug, it's how you *think
 *    different*", reference) → `Response.spim` (base64)
 * 3. [Spim.parse] the spim → `payload240` → [ClearAdiProvision.initSession] → session context
 * 4. [Cpim.build] with 124 RNG bytes (32/32/60), an empty extra blob and the GSA arg −2 →
 *    base64 into `request.cpim` → `POST <finish>` → `Response.{ptm, tk, X-Apple-I-MD-RINFO}`
 * 5. `tk` must be exactly 16 B (finish 17f1e31, error 0x8); key16 = `encrypt(session, NULL iv,
 *    tk)` (17f1eac); [ClearAdiProvision.decryptPtm] over the parsed Ptm payload → raw
 *    [ProvisionedData]
 *
 * The ProvisionedData→token-field mapping and the Cpim tail fields are the two remaining
 * TODO(live-capture) items; they are modeled honestly in [ClearAdiFraming] and surfaced here
 * as [cpimTailSeal] (required) and [finishSeed] (defaults to zero bytes).
 */
class ClearAnisetteProvider(
    private val http: IdsHttp,
    private val stateStore: ClearAdiStateStore,
    private val loginInfo: ClearAdiLoginInfo,
    private val rng: ClearAdiRng,
    private val cpimTailSeal: CpimTailSeal,
    /** Seed passed to decryptPTM (finish 17f2557's rcx) — zero bytes pending the live capture. */
    private val finishSeed: ByteArray = ByteArray(16),
    /** 16 random bytes identifying this client (reference `keychain_identifier`). */
    private val keychainIdentifier: ByteArray = rng.draw(16),
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    /** Load the stored state, or provision it through the GSA round trips. */
    suspend fun ensureProvisioned(): ClearAdiProvisionResult {
        stateStore.load()?.let { return resultFromJson(it) }
        val result = provision()
        stateStore.save(resultToJson(result))
        return result
    }

    /** The full start/finish provisioning exchange; persists nothing (caller decides). */
    suspend fun provision(): ClearAdiProvisionResult {
        val urls = lookupUrls()

        val startBody = XmlPlist.encode(mapOf("header" to emptyMap<String, String>(), "request" to emptyMap<String, String>()))
        val startResponse = exchange("start-provisioning", urls.startProvisioning, startBody)
        val spimB64 = responseString(startResponse, "Response", "spim")
        val spim = Spim.parse(Base64.getDecoder().decode(spimB64.trim()))
        val sessionCtx = ClearAdiProvision.initSession(spim.payload)

        // omnisette passes extra = [] and the GSA arg −2 (reference provision()).
        val cpim = Cpim.build(rng, extra = ByteArray(0), gsaArg = GSA_ARG, sessionCtx, spim.payload, cpimTailSeal)
        val finishBody = XmlPlist.encode(
            mapOf(
                "header" to emptyMap<String, String>(),
                "request" to mapOf("cpim" to Base64.getEncoder().encodeToString(cpim)),
            ),
        )
        val finishResponse = exchange("finish-provisioning", urls.finishProvisioning, finishBody)
        val response = responseDict(finishResponse)
        val ptm = Base64.getDecoder().decode(requireString(response, "Response", "ptm").trim())
        val tk = Base64.getDecoder().decode(requireString(response, "Response", "tk").trim())
        val rinfo = requireString(response, "Response", "X-Apple-I-MD-RINFO")

        if (tk.size != 16) {
            throw ClearAdiProvisioningException("tk not exactly 16 bytes (${tk.size} B; finish 17f1f11, error 0x8)")
        }
        val parsed = Ptm.parse(ptm)
        val key16 = ClearAdiProvision.encrypt(sessionCtx, null, tk)
        // count = payload.size / 16 (finish 17f2548); ProvisionedData is the first 0x78 B of
        // the decrypted output (17f2dec–17f2e56)
        val blocks = parsed.payload.size / 16
        val data = ClearAdiProvision.decryptPtm(key16, parsed.payload.copyOfRange(0, blocks * 16), finishSeed)
        return ClearAdiProvisionResult(ProvisionedData(data.copyOf(0x78)), rinfo)
    }

    /** The reference's fixed request-header set (`build_apple_request`, transcribed 1:1). */
    fun buildAppleRequestHeaders(nowEpochMs: Long): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        out["User-Agent"] = loginInfo.akdUserAgent
        out["X-Apple-Baa-E"] = "-10000"
        out["X-Apple-I-MD-LU"] = hex(sha256(keychainIdentifier))
        out["X-Mme-Device-Id"] = uuid(keychainIdentifier)
        out["X-Apple-Baa-Avail"] = "2"
        out["X-Mme-Client-Info"] = loginInfo.mmeClientInfo
        // The reference formats %+ here (…+00:00) and only the get_headers half rewrites to Z.
        out["X-Apple-I-Client-Time"] = iso8601Offset(nowEpochMs)
        out["Accept-Language"] = "en-US,en;q=0.9"
        out["X-Apple-Client-App-Name"] = "akd"
        out["Accept"] = "*/*"
        out["Content-Type"] = "application/x-www-form-urlencoded"
        out["X-Apple-Baa-UE"] = "AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000"
        out["X-Apple-Host-Baa-E"] = "-7066"
        out.putAll(loginInfo.hardwareHeaders)
        return out
    }

    /** The anisette header values (reference `AnisetteData::get_headers`, transcribed 1:1). */
    fun anisetteValues(state: ProvisionedAnisette, nowEpochMs: Long): Map<String, String> =
        ClearAdiAnisette(
            metadata = state.metadata,
            mid = state.mid,
            flavor = state.flavor,
            rinfo = state.rinfo,
            keychainIdentifier = keychainIdentifier,
            clientInfo = loginInfo.mmeClientInfo,
        ) { nowEpochMs }.headers()

    /** Flavor decision of the reference (anisette_clearadi.rs provision()): mme_client_info. */
    val flavor: Int get() = if (loginInfo.mmeClientInfo.contains("iPhone OS")) FLAVOR_IOS else FLAVOR_MAC

    private suspend fun lookupUrls(): ProvisioningUrls {
        val url = "https://$GSA_HOST/grandslam/GsService2/lookup"
        val response = http.get(url, buildAppleRequestHeaders(now()))
        if (response.status != 200) {
            throw ClearAdiProvisioningException("lookup GET $url → HTTP ${response.status}")
        }
        val root = try {
            Plist.parse(response.body)
        } catch (e: Exception) {
            throw ClearAdiProvisioningException("lookup response is not a plist: ${e.message}", e)
        }
        val urls = dictOrNull(root, "urls")
            ?: throw ClearAdiProvisioningException("lookup plist has no urls dict")
        return ProvisioningUrls(
            startProvisioning = requireString(urls, "midStartProvisioning"),
            finishProvisioning = requireString(urls, "midFinishProvisioning"),
        )
    }

    private suspend fun exchange(step: String, url: String, body: ByteArray): IdsHttpResponse {
        val response = http.post(url, buildAppleRequestHeaders(now()), body, "application/x-www-form-urlencoded")
        if (response.status != 200) {
            throw ClearAdiProvisioningException("$step POST $url → HTTP ${response.status}")
        }
        return response
    }

    /** Wall clock, injectable for tests (epoch ms). */
    internal fun now(): Long = clock()

    private fun sha256(bytes: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    /** `Uuid::from_bytes(identifier)` of the reference — the hyphenated lowercase form. */
    private fun uuid(bytes: ByteArray): String {
        require(bytes.size == 16) { "keychain identifier must be 16 bytes" }
        val bb = java.nio.ByteBuffer.wrap(bytes)
        return UUID(bb.long, bb.long).toString()
    }

    private data class ProvisioningUrls(val startProvisioning: String, val finishProvisioning: String)

    private fun responseString(response: IdsHttpResponse, vararg path: String): String =
        requireString(responseDict(response), *path)

    private fun responseDict(response: IdsHttpResponse): Map<String, Any?> {
        val root = try {
            Plist.parse(response.body)
        } catch (e: Exception) {
            throw ClearAdiProvisioningException("response is not a plist: ${e.message}", e)
        }
        @Suppress("UNCHECKED_CAST")
        return root as? Map<String, Any?>
            ?: throw ClearAdiProvisioningException("response plist root is not a dict")
    }

    private fun dictOrNull(map: Any?, key: String): Map<String, Any?>? {
        @Suppress("UNCHECKED_CAST")
        return (map as? Map<String, Any?>)?.get(key) as? Map<String, Any?>
    }

    private fun requireString(map: Map<String, Any?>, vararg path: String): String {
        var cur: Any? = map
        for (key in path) {
            @Suppress("UNCHECKED_CAST")
            cur = (cur as? Map<String, Any?>)?.get(key)
                ?: throw ClearAdiProvisioningException("plist path ${path.joinToString(".")} missing at $key")
        }
        return cur as? String
            ?: throw ClearAdiProvisioningException("plist path ${path.joinToString(".")} is not a string")
    }

    companion object {
        const val GSA_HOST = "gsa.apple.com"
        /** The GSA arg the omnisette reference passes (`ProvisioningSession::new(&spim, &[], -2, …)`). */
        const val GSA_ARG: Long = -2L
        const val FLAVOR_MAC = 0
        const val FLAVOR_IOS = 1
    }
}
