package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistDate
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.codec.integerOrNull
import dev.fenn.imessage.codec.longOrNull
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.courier.CourierCommands
import dev.fenn.imessage.courier.CourierFrame
import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.BagKeyMissingException
import dev.fenn.imessage.ids.IdsBagFetcher
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsIdentity
import dev.fenn.imessage.ids.IdsLookupClient
import dev.fenn.imessage.ids.IdsLookupException
import dev.fenn.imessage.ids.IdsLookupResult
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The `spd` decryption of spec §1.5: AES-256-CBC + PKCS7, key = HMAC-SHA256(K, `extra data
 * key:`), IV = the first 16 bytes of HMAC-SHA256(K, `extra data iv:`). The decrypted payload
 * is a plist carrying the per-service token map `t`, `acname`, `DsPrsId`, `adsid` and the
 * first/last name fields.
 */
object GsaSpdDecryptor {

    private val KEY_LABEL = "extra data key:".toByteArray(Charsets.US_ASCII)
    private val IV_LABEL = "extra data iv:".toByteArray(Charsets.US_ASCII)

    fun key(k: ByteArray): ByteArray = hmac(k, KEY_LABEL)

    fun iv(k: ByteArray): ByteArray = hmac(k, IV_LABEL).copyOfRange(0, 16)

    /** Decrypts and plist-parses [spd]; a failed PKCS7 pad or a non-dict payload fails loudly. */
    fun decrypt(spd: ByteArray, k: ByteArray): Map<String, Any?> {
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key(k), "AES"), IvParameterSpec(iv(k)))
        val plain = try {
            cipher.doFinal(spd)
        } catch (e: Exception) {
            throw GsaLoginException("spd decryption failed (§1.5): ${e.message}", e)
        }
        val parsed = try {
            Plist.parse(plain)
        } catch (e: PlistFormatException) {
            throw GsaLoginException("decrypted spd is not a plist: ${e.message}", e)
        }
        return stringKeyedDictOrNull(parsed)
            ?: throw GsaLoginException("decrypted spd is ${typeName(parsed)}, expected a dict")
    }

    private fun hmac(k: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(k, "HmacSHA256"))
        return mac.doFinal(message)
    }
}

/**
 * One entry of the §1.5 token map `t` (C59, keys recorded): service id → `token` (string) plus
 * `expiry` (epoch-ms) or `duration` (seconds).
 */
data class GsaServiceToken(
    /** The service id this entry is keyed by. */
    val serviceId: String,
    /** The `token` string. */
    val token: String,
    /** The `expiry` value, epoch-ms — null when the entry carries `duration` instead. */
    val expiresAtEpochMs: Long?,
    /** The `duration` value in seconds — null when the entry carries `expiry` instead. */
    val durationSeconds: Long?,
    val raw: Map<String, Any?>,
)

/**
 * The parsed §1.5 `spd` fields. Recorded keys (C59): the token map `t` with `token`/`expiry`/
 * `duration` inner keys, the TOP-LEVEL `GsIdmsToken` string (not inside `t`), `acname`,
 * `DsPrsId`, `adsid`, and the account-name keys `fn` (first name) / `ln` (last name).
 */
data class GsaSpd(
    /** The per-service token map `t`, keyed by service id. */
    val tokens: Map<String, GsaServiceToken>,
    /** The TOP-LEVEL `GsIdmsToken` string (§1.5 C59) — pairs with `adsid` in the identity token. */
    val gsIdmsToken: String?,
    val dsPrsId: Long?,
    val adsid: String?,
    val accountName: String?,
    /** The `fn` first name (optional string, §1.5 C59). */
    val firstName: String?,
    /** The `ln` last name (optional string, §1.5 C59). */
    val lastName: String?,
    val raw: Map<String, Any?>,
) {

    /**
     * The typed token entry for [serviceId]; loud on a missing entry (entries carry the
     * recorded `token`/`expiry`/`duration` keys — validated at parse time).
     */
    fun serviceToken(serviceId: String): GsaServiceToken =
        tokens[serviceId]
            ?: throw GsaLoginException("spd token map has no '$serviceId' entry (§1.5; has ${tokens.keys})")

    companion object {
        /** The recorded TOP-LEVEL spd key whose value pairs with `adsid` in the identity token (§1.5). */
        const val SERVICE_IDMS_TOKEN = "GsIdmsToken"

        fun parse(raw: Map<String, Any?>): GsaSpd {
            val tokensRaw = raw["t"]
                ?: throw GsaLoginException("spd has no 't' token-map dict (§1.5, got null)")
            val tokens = stringKeyedDictOrNull(tokensRaw)?.mapValues { (serviceId, entry) ->
                val entryDict = stringKeyedDictOrNull(entry)
                    ?: throw GsaLoginException("spd token-map entry is ${typeName(entry)}, expected a dict (§1.5)")
                readToken(serviceId, entryDict)
            } ?: throw GsaLoginException("spd has no 't' token-map dict (§1.5, got ${typeName(tokensRaw)})")
            return GsaSpd(
                tokens = tokens,
                gsIdmsToken = raw[SERVICE_IDMS_TOKEN] as? String,
                dsPrsId = longOrNull(raw["DsPrsId"]),
                adsid = raw["adsid"] as? String,
                accountName = raw["acname"] as? String,
                firstName = raw["fn"] as? String,
                lastName = raw["ln"] as? String,
                raw = raw,
            )
        }

        private fun readToken(serviceId: String, entry: Map<String, Any?>): GsaServiceToken {
            val token = entry["token"] as? String
                ?: throw GsaLoginException(
                    "spd token-map entry '$serviceId' has no 'token' string (§1.5, got ${typeName(entry["token"])})",
                )
            val expiry = longOrNull(entry["expiry"])
            val duration = longOrNull(entry["duration"])
            if (expiry == null && duration == null) {
                throw GsaLoginException(
                    "spd token-map entry '$serviceId' carries neither 'expiry' nor 'duration' (§1.5)",
                )
            }
            return GsaServiceToken(
                serviceId = serviceId,
                token = token,
                expiresAtEpochMs = expiry,
                durationSeconds = duration,
                raw = entry,
            )
        }
    }
}

/**
 * The §1.5 `X-Apple-Identity-Token`: base64 of `adsid:GsIdmsToken` (both from the decrypted
 * spd). All 2FA requests carry it (§1.5).
 */
fun gsaIdentityToken(adsid: String, idmsToken: String): String =
    Base64.getEncoder().encodeToString("$adsid:$idmsToken".toByteArray(Charsets.UTF_8))
