package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.ids.IdsHttp
import java.util.Base64

/**
 * The GSA `postdata` liveness event of spec §1.5 (rev 26, live 2026-10-03): a `liveness` event
 * declaring the device's services (`icloud`, `imessage`, `facetime`) against the account,
 * declared against `gsas.apple.com` (the §1.5 host split) — the hop that marks the device an
 * iCloud-capable device before the delegate sign-in can bind one (the §1.5 rev-25 409
 * `ICLOUD_UNSUPPORTED_DEVICE` blocker's precondition).
 *
 * Request shape (recorded): a `POST` of an XML-plist body with two top-level dictionaries,
 * `Header` (empty) and `Request` (the liveness event below), `Content-Type:
 * text/x-xml-plist`, the postdata-filtered anisette set (machine/device headers only — locale,
 * serial-bearing headers and the request uuid are dropped), fixed akd-variant headers, and two
 * account-binding headers: `X-Apple-I-UrlSwitch-Info` = base64(`<adsid>:postdata`) and
 * `X-Apple-HB-Token` = base64(`<adsid>:<hb token>`) — the `com.apple.gs.idms.hb` entry of the
 * post-2FA spd token map (§1.5 PET). The APNs push token rides the body as `ptkn` (uppercase
 * hex, §1.5 C59) when one has been minted; it is absent on a first login.
 */
data class GsaPostdataRequest(
    /** The decrypted spd `adsid` — pairs in both base64 headers. */
    val adsid: String,
    /** The `com.apple.gs.idms.hb` spd token — never logged. */
    val hbToken: String,
    /** A FRESH anisette set (one-time OTP — mint one per request, §1.5 rev-25 fact). */
    val anisette: Map<String, String>,
    /** The akd-form `X-Mme-Client-Info` ([GsaHeaderConfig.clientInfo]). */
    val clientInfo: String,
    /** The APNs push token hex — optional; absent on a first login (registration follows it). */
    val pushToken: String? = null,
)

/**
 * The GSA postdata client: one [post] per login, AFTER the delegate sign-in (rev 26: the
 * reference program order is sign-in first, postdata after — the delegate sign-in mints its
 * own Nas-Qualify blob at sign-in time, and the liveness event rides the post-sign-in
 * credentials; the earlier reverse-order note was wrong).
 */
class GsaPostdataClient(
    private val http: IdsHttp,
    private val logEvent: (String) -> Unit = {},
) {

    /**
     * Fires the liveness event; loud on a non-200 (the body carries no usable payload beyond
     * success).
     */
    suspend fun post(request: GsaPostdataRequest) {
        logEvent("gsa: postdata liveness (services=${SERVICES.joinToString(",")})")
        val headers = buildMap {
            putAll(filteredAnisette(request.anisette))
            put("Accept", "*/*")
            put("Accept-Language", "en-US,en;q=0.9")
            put("User-Agent", GsaHeaderConfig.AKD_USER_AGENT)
            put("X-Mme-Client-Info", request.clientInfo)
            put("X-Apple-I-Device-Configuration-Mode", "0")
            put("X-Apple-I-CDP-Status", "true")
            put("X-Apple-I-OT-Status", "true")
            put("X-Apple-I-CK-Presence", "true")
            put("X-Apple-I-DeviceUserMode", "0")
            put("X-Apple-AK-DataRecoveryService-Status", "1")
            put("X-Apple-I-TimeZone-Offset", "0")
            put("X-Apple-I-Service-Type", "itunesstore")
            put("X-Apple-I-Device-Type", "1")
            put("X-Apple-Requested-Partition", "0")
            put("X-Apple-I-UrlSwitch-Info", base64("${request.adsid}:postdata"))
            put("X-Apple-HB-Token", base64("${request.adsid}:${request.hbToken}"))
        }
        val body = linkedMapOf<String, Any?>(
            "Header" to linkedMapOf<String, Any?>(),
            "Request" to requestBody(request),
        )
        val response = http.post(ENDPOINT, headers, XmlPlist.encode(body), CONTENT_TYPE)
        if (response.status != 200) {
            throw GsaLoginException(
                "GSA postdata POST $ENDPOINT → HTTP ${response.status}${errorDetail(response.body)}",
            )
        }
    }

    /** Top-level error-shape facts only (keys, integer codes, error strings) — never tokens. */
    private fun errorDetail(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val dict = stringKeyedDictOrNull(try { Plist.parse(bytes) } catch (_: Exception) { return "" })
            ?: return " (body ${bytes.size}B)"
        val scalars = dict.entries.mapNotNull { (k, v) ->
            when {
                v is Int || v is Long -> "$k=$v"
                v is String && k !in setOf("dsid", "auth-token", "adsid") -> "$k=$v"
                v is Map<*, *> -> "$k keys=${stringKeyedDictOrNull(v)?.keys ?: v.keys}"
                else -> null
            }
        }.joinToString(", ")
        return " — body: $scalars"
    }

    /**
     * The liveness-event dict: the device announces the services [SERVICES] with recovery-key
     * generation on (`prkgen`).
     */
    private fun requestBody(request: GsaPostdataRequest) = linkedMapOf<String, Any?>(
        "cdpStatus" to true,
        "cfuids" to emptyList<Any?>(),
        "circleStatus" to true,
        "denyICloudWebAccess" to true,
        "dn" to DEVICE_NAME,
        "event" to EVENT_LIVENESS,
        "icloudMailEnabled" to false,
        "icscStatus" to true,
        "isLegacyContactAssignee" to 1,
        "loc" to "en_US",
        "otStatus" to true,
        "pkc" to "1",
        "prkgen" to true,
        "reason" to 5,
        "rep" to 1,
        "services" to SERVICES.toList(),
        "signinPartition" to 1,
        "stingrayDisabledIndicator" to false,
        "usrt" to 4,
        "ut" to 1,
    ).apply { request.pushToken?.let { put("ptkn", it) } }

    /**
     * The postdata anisette filter: only the machine/device anisette headers ride this
     * endpoint — locale, serial-bearing headers and the request uuid are dropped; the fixed
     * headers above replace them.
     */
    private fun filteredAnisette(anisette: Map<String, String>): Map<String, String> =
        anisette.filterKeys { key ->
            key.equals(ANISETTE_MD_LU, true) || key.equals(ANISETTE_RINFO, true) ||
                key.equals(ANISETTE_MD_M, true) || key.equals(ANISETTE_MD, true) ||
                key.equals(ANISETTE_DEVICE_ID, true) || key.equals(ANISETTE_CLIENT_TIME, true) ||
                key.equals(ANISETTE_TIME_ZONE, true)
        }

    private fun base64(value: String): String =
        Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))

    companion object {
        /** The postdata endpoint (§1.5: `gsas.apple.com`, with the S — not gsa). */
        const val ENDPOINT = "https://gsas.apple.com/grandslam/GsService2/postdata"

        const val CONTENT_TYPE = "text/x-xml-plist"
        const val EVENT_LIVENESS = "liveness"
        const val DEVICE_NAME = "Apple Device"

        /** The declared device services — the point of the whole hop. */
        val SERVICES = listOf("icloud", "imessage", "facetime")

        private const val ANISETTE_MD_LU = "X-Apple-I-MD-LU"
        private const val ANISETTE_RINFO = "X-Apple-I-MD-RINFO"
        private const val ANISETTE_MD_M = "X-Apple-I-MD-M"
        private const val ANISETTE_MD = "X-Apple-I-MD"
        private const val ANISETTE_DEVICE_ID = "X-Mme-Device-Id"
        private const val ANISETTE_CLIENT_TIME = "X-Apple-I-Client-Time"
        private const val ANISETTE_TIME_ZONE = "X-Apple-I-TimeZone"
    }
}
