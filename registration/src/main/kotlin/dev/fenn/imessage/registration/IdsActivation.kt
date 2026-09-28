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
import dev.fenn.imessage.ids.gunzipIfNeeded
import dev.fenn.imessage.ids.IdsLookupResult
import dev.fenn.imessage.ids.IdsSigning
import dev.fenn.imessage.ids.TunnelReply
import dev.fenn.imessage.ids.TunnelStatus
import dev.fenn.imessage.crypto.EcCrypto
import dev.fenn.imessage.crypto.MessageBody
import dev.fenn.imessage.crypto.PairEcEnvelope
import dev.fenn.imessage.crypto.PairEnvelope
import dev.fenn.imessage.crypto.PayloadCommands
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.util.Base64
import java.util.zip.GZIPOutputStream

/** Register/authenticate HTTP or parse failure (spec §1.2/§1.4). */
class IdsActivationException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The `private-device-data` dictionary of spec §1.4 — every wire key recorded, all values
 * strings except `dt` (integer 1). The relay/phone profile flips `m` and `s` from "0" to "1".
 * The four further keys both sources model (`c`, `ec`, `ktf`, `ktv`) are deliberately omitted,
 * as both implementations omit them.
 */
data class PrivateDeviceData(
    /** `pb` — OS build string. */
    val osBuild: String,
    /** `pn` — platform name. */
    val platformName: String,
    /** `pv` — OS version. */
    val osVersion: String,
    /** `u` — device UUID, uppercased. */
    val deviceUuid: String,
    /** `d` — seconds since the Apple epoch (2001-01-01), as a decimal string. */
    val appleEpochSeconds: Long,
    /** Relay/phone profile: `m`/`s` become "1" instead of "0" (§1.4). */
    val relayProfile: Boolean = false,
) {
    fun toDict(): Map<String, Any?> = linkedMapOf(
        "ap" to "0",
        "d" to appleEpochSeconds.toString(),
        "dt" to 1,
        "gt" to "0",
        "h" to "1",
        "m" to if (relayProfile) "1" else "0",
        "p" to "0",
        "pb" to osBuild,
        "pn" to platformName,
        "pv" to osVersion,
        "s" to if (relayProfile) "1" else "0",
        "t" to "0",
        "u" to deviceUuid.uppercase(),
        "v" to "1",
    )
}

/**
 * One user entry of spec §1.4. The recorded wire keys are `user-id`, `uris`, `tag`,
 * `client-data` and `kt-loggable-data`; `tag` is present only for phone users ("SIM", "SIM2",
 * …). [userId] is the plain profile-ID string — phone users carry the `P:` prefix here, and
 * that same string is the `x-auth-user-id-<N>` header value (§1.4, register-only).
 *
 * [uris] are single-key `tel:`/`mailto:` dictionaries fetched from the server and echoed back
 * — never constructed locally (§1.4); fetching them is the caller's step.
 *
 * [clientData] rides verbatim: the base wire keys are recorded (§1.4: `public-message-identity-key`,
 * `public-message-identity-version`, `ec-version`, `public-message-identity-ngm-version`,
 * `public-message-ngm-device-prekey-data-key`, `kt-version` plus the `supports-*` booleans) but
 * the exact capability set is disagreed between the sources (C3) and the key structures belong
 * to the identity component — the caller assembles the dict. Same for [ktLoggableData]'s
 * protobuf contents (C52).
 */
data class RegisterUser(
    val userId: String,
    val uris: List<Map<String, String>>,
    val tag: String?,
    /** The per-user auth key of §1.4 (2048-bit RSA, §1.2). */
    val authKey: PrivateKey,
    /** The auth certificate this user's CSR was exchanged for (§1.2). */
    val authCertificateDer: ByteArray,
    val clientData: Map<String, Any?>,
    val ktLoggableData: ByteArray?,
) {
    fun toDict(): Map<String, Any?> = buildMap {
        put("user-id", userId)
        put("uris", uris)
        put("client-data", clientData)
        tag?.let { put("tag", it) }
        ktLoggableData?.let { put("kt-loggable-data", it) }
    }
}

/**
 * One capability record of a §1.4 service entry: `flags` (int), `name` (string), `version`
 * (int). The record both sources send is name "Messenger", version 1 — but the flags value is
 * disagreed (17 vs 1, capture-bound C3); the default follows the section's prose, which reads
 * the 17 variant first.
 */
data class RegisterCapability(
    val flags: Int = 17,
    val name: String = "Messenger",
    val version: Int = 1,
) {
    fun toDict(): Map<String, Any?> = linkedMapOf(
        "flags" to flags,
        "name" to name,
        "version" to version,
    )
}

/**
 * One `services` array entry of spec §1.4: `service`, `sub-services`, `users`, `capabilities`.
 * The sub-service list is disagreed (four topics vs seven, C3): [subServices] defaults to the
 * four-topic list the section's prose reads first; the seven-topic variant is
 * [SUB_SERVICES_SEVEN]. The users array rides inside the service entry — §1.4 records the
 * request as exactly eight top-level keys, none beyond.
 */
data class RegisterService(
    val service: String,
    val subServices: List<String> = SUB_SERVICES,
    val users: List<RegisterUser>,
    val capabilities: List<RegisterCapability> = listOf(RegisterCapability()),
) {
    fun toDict(): Map<String, Any?> = linkedMapOf(
        "capabilities" to capabilities.map { it.toDict() },
        "service" to service,
        "sub-services" to subServices,
        "users" to users.map { it.toDict() },
    )

    companion object {
        /** The iMessage service value (§1.4). */
        const val MADRID = "com.apple.madrid"

        /** Four topics — the first-recorded sub-service list (C3). */
        val SUB_SERVICES = listOf(
            "com.apple.private.alloy.sms",
            "com.apple.private.alloy.gelato",
            "com.apple.private.alloy.biz",
            "com.apple.private.alloy.gamecenter.imessage",
        )

        /** The second-recorded variant: the four topics plus three more (C3). */
        val SUB_SERVICES_SEVEN = SUB_SERVICES + listOf(
            "com.apple.private.alloy.safetymonitor",
            "com.apple.private.alloy.safetymonitor.ownaccount",
            "com.apple.private.alloy.askto",
        )
    }
}

/**
 * The register body of spec §1.4, encoded as an XML plist — exactly the eight recorded
 * top-level keys, none beyond (§1.4): `device-name`, `hardware-version`, `language`,
 * `os-version`, `software-version`, `private-device-data`, `services`, `validation-data`.
 */
data class RegisterBody(
    val deviceName: String,
    val hardwareVersion: String,
    val language: String,
    val osVersion: String,
    val softwareVersion: String,
    val privateDeviceData: PrivateDeviceData,
    val services: List<RegisterService>,
    /** The `validation-data` blob (§1.1) — carried verbatim; minting it is C5/C56-blocked. */
    val validationData: ByteArray,
) {
    fun toDict(): Map<String, Any?> = linkedMapOf(
        "device-name" to deviceName,
        "hardware-version" to hardwareVersion,
        "language" to language,
        "os-version" to osVersion,
        "software-version" to softwareVersion,
        "private-device-data" to privateDeviceData.toDict(),
        "services" to services.map { it.toDict() },
        "validation-data" to validationData,
    )

    /** The body's distinct users, in first-occurrence order — one signature per user (§1.4). */
    val users: List<RegisterUser>
        get() = services.flatMap { it.users }.distinctBy { it.userId }
}

/**
 * Everything a register request needs (spec §1.4). Header wire names are the recorded ones:
 * the `x-push-*`/`x-auth-*-<N>` signature sets (§1.4) plus `x-protocol-version` and
 * `user-agent` (§1.2/§2.1 record the names).
 */
data class RegisterConfig(
    /** The 32-byte APNs connect token, signed into the payload and sent as `x-push-token`. */
    val pushToken: ByteArray,
    val pushKey: PrivateKey,
    /** The Albert device certificate — issued by [AlbertActivator] (§1.2). */
    val pushCertificateDer: ByteArray,
    /** "1640" hardcoded in one source, "1660" in the other's fixtures — C2 open. */
    val protocolVersion: String,
    /** `com.apple.invitation-registration [<name>,<version>,<build>,<hardware>]` (§1.4). */
    val userAgent: String,
)

/** A per-URI result of the register response (§1.4): `uri` + `status`. */
data class IdsRegisterUriResult(
    val uri: String,
    val status: Int?,
)

/** The `alert` object of the register response (§1.4): `title`/`body`/`button` + nested `action`. */
data class IdsRegisterAlert(
    val title: String?,
    val body: String?,
    val button: String?,
    val action: IdsRegisterAlertAction?,
)

/** The nested `action` object of a register `alert` (§1.4): `button`, `type`, `url`. */
data class IdsRegisterAlertAction(
    val button: String?,
    val type: String?,
    val url: String?,
)

/** A per-user result of the register response (§1.4 keys `uris`, `user-id`, `cert`, `status`, `alert`). */
data class IdsRegisterUserResult(
    val userId: String?,
    val status: Int?,
    /**
     * §6.1: a status equal to the configured refresh-credentials marker marks that auth pair
     * for refresh. The marker string is capture-bound — caller-supplied, never guessed.
     */
    val refreshCredentials: Boolean,
    /** The X.509 identity certificate (DER) to store. */
    val cert: ByteArray?,
    val uris: List<IdsRegisterUriResult>,
    val alert: IdsRegisterAlert?,
    /** §6.1: seconds from registration until re-registration; absent → cert `notAfter` − 5 min. */
    val nextHbi: Long?,
    val raw: Map<String, Any?>,
)

/** A per-service result of the register response (§1.4: `service`, `users`, `status`). */
data class IdsRegisterServiceResult(
    val service: String?,
    val status: Int?,
    val refreshCredentials: Boolean,
    val users: List<IdsRegisterUserResult>,
    val raw: Map<String, Any?>,
)

/**
 * The register response of spec §1.4. Top level `status`, `message`, `retry-interval`,
 * `services` — one source names all four, the other reads only `status` and `services` (C57);
 * the spec's wording models all four, so the two read-only ones stay optional here.
 */
data class IdsRegisterResponse(
    val status: Int,
    val message: String?,
    val retryInterval: Long?,
    val services: List<IdsRegisterServiceResult>,
    val raw: Map<String, Any?>,
) {
    companion object {
        const val STATUS_OK = 0
        /** Contact Key Verification or Advanced Data Protection enabled (§1.4). */
        const val STATUS_INCOMPATIBLE = 6001
        const val STATUS_TRANSIENT_RETRY = 6004
        const val STATUS_BAD_AUTHENTICATION = 6005
        const val STATUS_ACCESS_DISABLED = 6009
        const val STATUS_ALIAS_REMOVED = 5052
    }
}

/**
 * IDS register client per spec §1.4: POST the XML-plist body to the bag's `id-register` URL,
 * signed once with the push key and once per user with that user's auth key (§1.4's indexed
 * header sets). The body goes out with the recorded content type and no gzip — the
 * gzip-vs-plain disagreement is C3 and the un-gzipped variant is the lower-assumption one.
 *
 * [refreshCredentialsMarker] is the §6.1 "refresh credentials" status string — capture-bound,
 * so caller-supplied. With it unset (the default), any string-valued per-user/per-service
 * status fails the parse loudly rather than being silently dropped.
 */
class IdsRegistrar(
    private val http: IdsHttp,
    private val bag: Bag,
    private val config: RegisterConfig,
    private val refreshCredentialsMarker: String? = null,
) {

    suspend fun register(body: RegisterBody): IdsRegisterResponse {
        val url = bag.url(BAG_KEY)
        val encoded = XmlPlist.encode(body.toDict())
        val headers = signatureHeaders(encoded, body.users)
        headers[PROTOCOL_VERSION_HEADER] = config.protocolVersion
        headers[USER_AGENT_HEADER] = config.userAgent
        val response = http.post(url, headers, encoded, CONTENT_TYPE)
        if (response.status != 200) throw IdsActivationException("POST $url → HTTP ${response.status}")
        return parseResponse(gunzipIfNeeded(response.body))
    }

    /** §1.4: push set + per-user indexed sets, all over the same signed tuple. */
    private fun signatureHeaders(
        encodedBody: ByteArray,
        users: List<RegisterUser>,
    ): LinkedHashMap<String, String> {
        val fields = listOf(
            BAG_KEY.toByteArray(Charsets.UTF_8),
            EMPTY_QUERY,
            encodedBody,
            config.pushToken,
        )
        val out = LinkedHashMap<String, String>()
        val pushNonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS)
        out["x-push-nonce"] = base64(pushNonce)
        out["x-push-cert"] = base64(config.pushCertificateDer)
        out["x-push-sig"] = base64(IdsSigning.sign(config.pushKey, pushNonce, fields))
        out["x-push-token"] = base64(config.pushToken)
        users.forEachIndexed { i, user ->
            val nonce = IdsSigning.nonce(IdsSigning.TYPE_HTTPS)
            out["x-auth-user-id-$i"] = user.userId
            out["x-auth-nonce-$i"] = base64(nonce)
            out["x-auth-cert-$i"] = base64(user.authCertificateDer)
            out["x-auth-sig-$i"] = base64(IdsSigning.sign(user.authKey, nonce, fields))
        }
        return out
    }

    private fun parseResponse(bytes: ByteArray): IdsRegisterResponse {
        val parsed = try {
            Plist.parse(bytes)
        } catch (e: PlistFormatException) {
            throw IdsActivationException("register response is not a plist: ${e.message}", e)
        }
        val dict = stringKeyedDictOrNull(parsed)
            ?: throw IdsActivationException("register response is ${typeName(parsed)}, expected a dict")
        val status = integerOrNull(dict["status"])
            ?: throw IdsActivationException(
                "register response has no integer 'status' (${typeName(dict["status"])}) — spec §1.4 records one",
            )
        val services = when (val value = dict["services"]) {
            null -> emptyList()
            is List<*> -> value.mapIndexed { i, entry ->
                val service = stringKeyedDictOrNull(entry)
                    ?: throw IdsActivationException("register services[$i] is ${typeName(entry)}, expected a dict")
                val (serviceStatus, serviceRefresh) = parseStatus(service["status"], "services[$i]")
                IdsRegisterServiceResult(
                    service = service["service"] as? String,
                    status = serviceStatus,
                    refreshCredentials = serviceRefresh,
                    users = when (val users = service["users"]) {
                        null -> emptyList()
                        is List<*> -> users.mapIndexed { j, entry ->
                            parseUser(stringKeyedDictOrNull(entry)
                                ?: throw IdsActivationException(
                                    "register services[$i].users[$j] is ${typeName(entry)}, expected a dict",
                                ), "services[$i].users[$j]")
                        }
                        else -> throw IdsActivationException(
                            "register services[$i].users is ${typeName(users)}, expected an array",
                        )
                    },
                    raw = service,
                )
            }
            else -> throw IdsActivationException("register 'services' is ${typeName(value)}, expected an array")
        }
        return IdsRegisterResponse(
            status = status,
            message = dict["message"] as? String,
            retryInterval = longOrNull(dict["retry-interval"]),
            services = services,
            raw = dict,
        )
    }

    private fun parseUser(user: Map<String, Any?>, where: String): IdsRegisterUserResult {
        val (status, refresh) = parseStatus(user["status"], where)
        return IdsRegisterUserResult(
            userId = user["user-id"] as? String,
            status = status,
            refreshCredentials = refresh,
            cert = user["cert"] as? ByteArray,
            uris = when (val uris = user["uris"]) {
                null -> emptyList()
                is List<*> -> uris.mapIndexed { k, entry ->
                    val uri = stringKeyedDictOrNull(entry)
                        ?: throw IdsActivationException("$where.uris[$k] is ${typeName(entry)}, expected a dict")
                    IdsRegisterUriResult(
                        uri = uri["uri"] as? String
                            ?: throw IdsActivationException("$where.uris[$k] has no 'uri' string"),
                        status = integerOrNull(uri["status"]),
                    )
                }
                else -> throw IdsActivationException("$where.uris is ${typeName(uris)}, expected an array")
            },
            alert = (user["alert"] as? Map<*, *>)?.let { alert ->
                IdsRegisterAlert(
                    title = alert["title"] as? String,
                    body = alert["body"] as? String,
                    button = alert["button"] as? String,
                    action = (alert["action"] as? Map<*, *>)?.let { action ->
                        IdsRegisterAlertAction(
                            button = action["button"] as? String,
                            type = action["type"] as? String,
                            url = action["url"] as? String,
                        )
                    },
                )
            },
            nextHbi = longOrNull(user["next-hbi"]),
            raw = user,
        )
    }

    /** A status is an integer, or the §6.1 "refresh credentials" marker when configured. */
    private fun parseStatus(value: Any?, where: String): Pair<Int?, Boolean> = when (value) {
        null -> null to false
        is Long -> value.toInt() to false
        is Int -> value to false
        is String ->
            if (value == refreshCredentialsMarker) null to true
            else throw IdsActivationException(
                "$where status is the string '$value' — if that is the 'refresh credentials' " +
                    "marker (spec §6.1), configure it explicitly",
            )
        else -> throw IdsActivationException("$where status is ${typeName(value)}, expected an integer")
    }

    private fun base64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    companion object {
        /** Bag key for the register endpoint (spec §1.2/§1.4). */
        const val BAG_KEY = "id-register"

        /** The recorded content type (§1.4); the other source sends none — C3. */
        const val CONTENT_TYPE = "application/x-apple-plist"

        /** Recorded header wire names (§1.2/§2.1). */
        const val PROTOCOL_VERSION_HEADER = "x-protocol-version"
        const val USER_AGENT_HEADER = "user-agent"

        private val EMPTY_QUERY = ByteArray(0)
    }
}

/**
 * The `authentication-data` dict of spec §1.2: `auth-token` for the Apple/DS flow, or
 * `push-token` + `sigs` (array) for the phone flow. The value encodings of `push-token` and
 * `sigs` are not recorded (only their key names are) — they are supplied verbatim.
 */
sealed interface AuthenticationData {

    data class AuthToken(val token: String) : AuthenticationData

    data class Push(val pushToken: Any?, val sigs: List<Any?>) : AuthenticationData

    fun toDict(): Map<String, Any?> = when (this) {
        is AuthToken -> mapOf("auth-token" to token)
        is Push -> mapOf("push-token" to pushToken, "sigs" to sigs)
    }
}

/** The authenticate response of spec §1.2: flat `status` + `cert`, no per-user nesting. */
data class IdsAuthenticateResponse(
    val status: Int,
    /** The authentication certificate this exchange issues (DER) — enables registration (§1.2). */
    val cert: ByteArray?,
    val raw: Map<String, Any?>,
)

/**
 * The §1.2 authenticate exchange. One authentication per user, to the `id-authenticate-ds-id`
 * (Apple/DS flow) or `id-authenticate-phone-number` bag URL; phone realm user ids have the
 * "P:<number>" form. The request body is an XML plist with keys `authentication-data`, `csr`
 * (DER), `realm-user-id`; the CSR's CN is the hex SHA-1 of the realm user id ([IdsCsrBuilder]).
 *
 * Headers are ONLY `user-agent` and `x-protocol-version` plus `content-encoding: gzip` (the
 * §1.2 extraction; the §1.4 signature header sets are NOT applied to authenticate). The
 * SMS-less multi-user route needs carrier EAP-AKA data (C7) and is out of scope.
 *
 * Two §1.2 values ride C57 as caller parameters on the CSR builder: the CN hex case
 * ([HexCase], default UPPER) and the CSR self-signature hash ([CsrSignatureHash], default
 * SHA-1) — both built before this class is reached.
 */
class IdsAuthenticator(
    private val http: IdsHttp,
    private val bag: Bag,
    private val protocolVersion: String,
    private val userAgent: String,
) {

    suspend fun authenticate(
        bagKey: String,
        realmUserId: String,
        csrDer: ByteArray,
        authenticationData: AuthenticationData,
    ): IdsAuthenticateResponse {
        require(bagKey == BAG_KEY_DS_ID || bagKey == BAG_KEY_PHONE_NUMBER) {
            "bag key must be $BAG_KEY_DS_ID or $BAG_KEY_PHONE_NUMBER (spec §1.2); '$bagKey' is neither"
        }
        val url = bag.url(bagKey)
        val body = linkedMapOf<String, Any?>(
            "authentication-data" to authenticationData.toDict(),
            "csr" to csrDer,
            "realm-user-id" to realmUserId,
        )
        val encoded = gzip(XmlPlist.encode(body))
        val headers = linkedMapOf(
            USER_AGENT_HEADER to userAgent,
            PROTOCOL_VERSION_HEADER to protocolVersion,
            "content-encoding" to "gzip",
        )
        val response = http.post(url, headers, encoded, CONTENT_TYPE)
        if (response.status != 200) throw IdsActivationException("POST $url → HTTP ${response.status}")
        return parseResponse(gunzipIfNeeded(response.body))
    }

    private fun parseResponse(bytes: ByteArray): IdsAuthenticateResponse {
        val parsed = try {
            Plist.parse(bytes)
        } catch (e: PlistFormatException) {
            throw IdsActivationException("authenticate response is not a plist: ${e.message}", e)
        }
        val dict = stringKeyedDictOrNull(parsed)
            ?: throw IdsActivationException("authenticate response is ${typeName(parsed)}, expected a dict")
        return IdsAuthenticateResponse(
            status = integerOrNull(dict["status"])
                ?: throw IdsActivationException(
                    "authenticate response has no integer 'status' (${typeName(dict["status"])}) — spec §1.2 records one",
                ),
            cert = dict["cert"] as? ByteArray,
            raw = dict,
        )
    }

    private fun gzip(bytes: ByteArray): ByteArray = ByteArrayOutputStream(bytes.size).use { buffer ->
        GZIPOutputStream(buffer).use { it.write(bytes) }
        buffer.toByteArray()
    }

    companion object {
        const val BAG_KEY_DS_ID = "id-authenticate-ds-id"
        const val BAG_KEY_PHONE_NUMBER = "id-authenticate-phone-number"

        /** Not recorded for authenticate (§1.2); the register content type is the nearest fact. */
        const val CONTENT_TYPE = "application/x-apple-plist"

        const val PROTOCOL_VERSION_HEADER = "x-protocol-version"
        const val USER_AGENT_HEADER = "user-agent"
    }
}
