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
/** ADI provisioning exchange failure (spec §1.1). */
class AdiProvisioningException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * One caller-assembled provisioning round trip (spec §1.1: start/finish provisioning with
 * gsa.apple.com). Everything on the wire that the spec does not record — the endpoint paths,
 * the request body keys, the body encoding, the anisette/auth header usage at provisioning
 * time (C56) — is supplied by the caller here; nothing is invented.
 */
data class AdiProvisioningRequest(
    val url: String,
    val headers: Map<String, String>,
    val body: ByteArray,
    val contentType: String,
)

/**
 * One provisioning response. [body] is always the raw bytes; [plist] is the body parsed as a
 * string-keyed plist dict, or null when the body is not one — the response encoding is not
 * recorded (TODO(capture) C6), so a null here means "unrecorded encoding hit", and the
 * response's field names are read by the caller off the raw map, never guessed here.
 */
data class AdiProvisioningResponse(
    val status: Int,
    val headers: Map<String, String>,
    val body: ByteArray,
    val plist: Map<String, Any?>?,
)

/**
 * The ADI provisioning exchange plumbing of spec §1.1: a start-provisioning round trip and a
 * finish-provisioning round trip against gsa.apple.com, whose responses carry the machine
 * tokens the anisette headers derive from. Only the host and the start/finish shape are
 * recorded — paths, encodings, and field names stay caller-supplied/raw (TODO(capture) C6),
 * with the transport injected so tests script the exchange and production stays gated.
 */
class AdiProvisioner(private val http: IdsHttp) {

    suspend fun start(request: AdiProvisioningRequest): AdiProvisioningResponse =
        exchange("start-provisioning", request)

    suspend fun finish(request: AdiProvisioningRequest): AdiProvisioningResponse =
        exchange("finish-provisioning", request)

    private suspend fun exchange(step: String, request: AdiProvisioningRequest): AdiProvisioningResponse {
        val response = http.post(request.url, request.headers, request.body, request.contentType)
        if (response.status != 200) {
            throw AdiProvisioningException("$step POST ${request.url} → HTTP ${response.status}")
        }
        return AdiProvisioningResponse(
            status = response.status,
            headers = response.headers,
            body = response.body,
            plist = plistDictOrNull(response.body, step, request.url),
        )
    }

    private fun plistDictOrNull(body: ByteArray, step: String, url: String): Map<String, Any?>? =
        try {
            stringKeyedDictOrNull(Plist.parse(body))
        } catch (_: PlistFormatException) {
            null
        } catch (e: Exception) {
            throw AdiProvisioningException("$step response from $url failed to decode: ${e.message}", e)
        }

    companion object {
        /** The one recorded host fact (spec §1.1); the paths on it are unrecorded. */
        const val GSA_HOST = "gsa.apple.com"
    }
}
