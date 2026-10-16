package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.PlistFormatException
import dev.fenn.imessage.codec.integerOrNull
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.codec.typeName
import dev.fenn.imessage.ids.Bag
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.gunzipIfNeeded
import java.security.PrivateKey
import java.util.Base64

/**
 * The §1.4 handle fetch — the reference client's `id-get-handles`, the step that yields the
 * `uris` a register echoes back [rustpush:ids/user.rs:791 `get_possible_handles`, called from
 * `register` at :987 for every user before the body is built].
 *
 * That is why [RegisterUser.uris] must be server-supplied: the register echoes the user's
 * registered handle list, it does not invent one. The reference does this fetch per user, once,
 * and then puts the same list on every service entry.
 *
 * The request is bare by design: GET, no body, no user-agent, and the signature headers WITHOUT
 * an index postfix (`base_request` at :712 appends `x-auth-user-id` unindexed, then
 * `sign(..., KeyType::Auth, aps, None)` → `x-auth-*`; the push signature rides along the same
 * payload tuple). Headers carried: `x-protocol-version`, `x-push-token`, `x-auth-user-id`, and
 * the six signature headers. A non-zero `status` is the reference's `AuthInvalid(status)`.
 */
class IdsHandleFetcher(
    private val http: IdsHttp,
    private val bag: Bag,
    private val config: RegisterConfig,
) {

    suspend fun handles(
        userId: String,
        authKey: PrivateKey,
        authCertificateDer: ByteArray,
    ): List<String> {
        val url = bag.url(BAG_KEY)
        // The §1.4 signed tuple for a bodiless GET: bag key, empty query, empty body, push token.
        val fields = listOf(BAG_KEY.toByteArray(Charsets.UTF_8), EMPTY_QUERY, EMPTY_BODY, config.pushToken)
        val headers = LinkedHashMap<String, String>()
        headers[IdsRegistrar.PROTOCOL_VERSION_HEADER] = config.protocolVersion
        headers["x-push-token"] = base64(config.pushToken)
        headers["x-auth-user-id"] = userId
        val pushNonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS)
        headers["x-push-nonce"] = base64(pushNonce)
        headers["x-push-cert"] = base64(config.pushCertificateDer)
        headers["x-push-sig"] = base64(IdsSigning.sign(config.pushKey, pushNonce, fields))
        val authNonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS)
        headers["x-auth-nonce"] = base64(authNonce)
        headers["x-auth-cert"] = base64(authCertificateDer)
        headers["x-auth-sig"] = base64(IdsSigning.sign(authKey, authNonce, fields))

        val response = http.get(url, headers)
        if (response.status != 200) throw IdsActivationException("GET $url → HTTP ${response.status}")
        return parse(gunzipIfNeeded(response.body))
    }

    private fun parse(bytes: ByteArray): List<String> {
        val parsed = try {
            Plist.parse(bytes)
        } catch (e: PlistFormatException) {
            throw IdsActivationException("id-get-handles response is not a plist: ${e.message}", e)
        }
        val dict = stringKeyedDictOrNull(parsed)
            ?: throw IdsActivationException("id-get-handles response is ${typeName(parsed)}, expected a dict")
        val status = integerOrNull(dict["status"])
            ?: throw IdsActivationException(
                "id-get-handles response has no integer 'status' (${typeName(dict["status"])})",
            )
        if (status != 0) throw IdsActivationException("id-get-handles status $status")
        val handles = dict["handles"] ?: return emptyList()
        if (handles !is List<*>) {
            throw IdsActivationException("id-get-handles 'handles' is ${typeName(handles)}, expected an array")
        }
        return handles.mapIndexed { i, entry ->
            val handle = stringKeyedDictOrNull(entry)
                ?: throw IdsActivationException("id-get-handles handles[$i] is ${typeName(entry)}, expected a dict")
            handle["uri"] as? String
                ?: throw IdsActivationException("id-get-handles handles[$i] has no 'uri' string")
        }
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    companion object {
        /** Bag key for the handle endpoint (spec §1.2/§1.4). */
        const val BAG_KEY = "id-get-handles"

        private val EMPTY_QUERY = ByteArray(0)
        private val EMPTY_BODY = ByteArray(0)
    }
}
