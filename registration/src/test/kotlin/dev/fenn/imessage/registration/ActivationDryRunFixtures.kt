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
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * In-memory [IdsStateDao] backing the dry run's [IdsStore]: the Room layer needs an Android
 * Context (see [IdsStoreTest]'s header note), so the dry run drives the real [IdsStore] and
 * entity/DAO surface over this DAO — the persistence contract (upsert, read-modify-write,
 * registered-user rows) is exercised; only SQLite is swapped out.
 */
internal class InMemoryIdsStateDao : IdsStateDao {

    var accountRow: IdsAccountEntity? = null
    private val users = LinkedHashMap<String, IdsRegisteredUserEntity>()
    private val results = LinkedHashMap<String, IdsCachedResultEntity>()
    private val identities = LinkedHashMap<String, MutableList<IdsCachedIdentityEntity>>()

    override suspend fun account(): IdsAccountEntity? = accountRow

    override suspend fun upsertAccount(entity: IdsAccountEntity) {
        accountRow = entity
    }

    override suspend fun registeredUsers(): List<IdsRegisteredUserEntity> = users.values.toList()

    override suspend fun registeredUser(userId: String): IdsRegisteredUserEntity? = users[userId]

    override suspend fun upsertUser(user: IdsRegisteredUserEntity) {
        users[user.userId] = user
    }

    override suspend fun removeUser(userId: String) {
        users.remove(userId)
    }

    override suspend fun cachedResult(handle: String): IdsCachedResultWithIdentities? =
        results[handle]?.let { IdsCachedResultWithIdentities(it, identities[handle].orEmpty()) }

    override suspend fun cachedHandles(): List<String> = results.keys.toList()

    override suspend fun upsertCachedResult(result: IdsCachedResultEntity) {
        results[result.handle] = result
    }

    override suspend fun upsertCachedIdentities(list: List<IdsCachedIdentityEntity>) {
        list.forEach { identity ->
            identities.getOrPut(identity.handle) { mutableListOf() }.add(identity)
        }
    }

    override suspend fun deleteCachedResult(handle: String) {
        results.remove(handle)
        identities.remove(handle)
    }

    override suspend fun deleteCacheExcept(key: String) {
        results.entries.removeIf { it.value.cacheKeySha1 != key }
    }

    override suspend fun clearCache() {
        results.clear()
        identities.clear()
    }
}

/**
 * The scripted fake-Apple environment of the activation dry run: ONE routing [IdsHttp] that
 * plays every server in the recorded journey — the IDS bag, the two validation endpoints,
 * gsa.apple.com ADI provisioning, albert activation, the GSA SRP/2FA login, the iCloud
 * sign-in, and the authenticate/register endpoints.
 *
 * Every handler is assertive: it checks the recorded wire shape of its hop and fails loudly
 * (`require`, with the spec section in the message) on a wrong shape, a wrong header set, or
 * an unexpected path. What a fake server cannot know (client-generated keys, the minted
 * validation blob, the test OTP) arrives via `expected*` setters the test wires after minting
 * — then it is asserted server-side like everything else.
 *
 * The GSA SRP half is the same second independent server-side implementation of the §1.5
 * formulas the GsaLoginChainTest uses (K derived from the client's A; identity hash over the
 * EMPTY username; M1/M2 over the recorded concatenations).
 */
internal class DryRunAppleEnvironment(
    /** SHA-256 of the raw password — the test's password-hash input to the SRP verifier. */
    private val passwordHash: ByteArray,
) : IdsHttp {

    // ---- endpoints (recorded hosts/paths; the bag-key URLs are client-resolved fixtures) ----

    val certUrl = "https://id.example.apple.com/WebObjects/VCValidation.woa/wa/validationCert"
    val initUrl = "https://id.example.apple.com/WebObjects/VCValidation.woa/wa/initializeValidation"
    val adiStartUrl = "https://${AdiProvisioner.GSA_HOST}/adi/start-provisioning"
    val adiFinishUrl = "https://${AdiProvisioner.GSA_HOST}/adi/finish-provisioning"
    val authenticateUrl = "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS"
    val registerUrl = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register"

    // ---- fixture data the server side owns ----

    /** The §1.1 step-1 `cert` payload (any bytes — the step-3 reconstruction consumes them verbatim). */
    val validationCert = ByteArray(24) { (it + 1).toByte() }

    /** The server's P-256 key-agreement point, served as the §1.1 step-2 `session-info`. */
    private val sessionInfoPoint =
        EcCrypto.compress(EcKeys.p256(SecureRandom()).public)

    /** The machine identifier the ADI finish response yields — its wire form is unrecorded (C6). */
    val machineIdentifier = ByteArray(32) { (it + 0x11).toByte() }
    private val adiSessionBytes = ByteArray(8) { (it + 0x40).toByte() }

    /** Real, parseable X.509 stand-ins (staged Apple intermediates) for the two issued certs. */
    val deviceCertDer = resourceDer("/imessage/AppleServerAuthenticationCA-2010.pem")
    val identityCertDer = resourceDer("/imessage/AppleServerAuthenticationCA2-G3.pem")
    val deviceCertPem = Pem.encode(Pem.CERTIFICATE_TYPE, deviceCertDer)

    /** The handle the environment "has registered" for this account (§1.4 URI echo). */
    val registeredUri = "tel:+15550001111"

    /** The trusted-device 2FA code the environment accepts (§1.5). */
    val securityCode = "987654"

    // ---- credentials the environment serves; its handlers assert the client echoes them ----

    val adsid = "adsid-1"
    val profileId = "profile-id-1"
    val authToken = "ids-auth-token-1"

    /** Client-minted values, wired by the test right after they exist — then asserted server-side. */
    var expectedValidationBlob: ByteArray? = null
    var expectedCsrDer: ByteArray? = null

    // ---- observed state ----

    var bagFetches = 0
    var validationCertFetches = 0
    var initializeCount = 0
    var adiStartCount = 0
    var adiFinishCount = 0
    var albertActivations = 0
    var gsaInitCount = 0
    var gsaCompleteCount = 0
    var trustedDeviceTriggers = 0
    var validateCount = 0
    var signInCount = 0
    var authenticateCount = 0
    var registerCount = 0

    var delegateUsername: String? = null
    var delegatePet: String? = null
    var validateSecurityCode: String? = null

    /** The recorded register call (headers + exact body bytes), for the test-side §1.4 signature verification. */
    class RegisterCall(val headers: Map<String, String>, val body: ByteArray)
    val registerCalls = mutableListOf<RegisterCall>()

    private val calls = mutableListOf<Pair<String, String>>()
    fun callUrls(): List<String> = calls.map { it.second }

    // ---- GSA SRP server state ----

    private val group = GsaSrpGroup
    private val salt = ByteArray(16) { it.toByte() }
    private var session: Session? = null
    private var petCounter = 0

    private class Session(
        val aPublic: ByteArray,
        val serverPublic: ByteArray,
        val verifier: BigInteger,
        val serverPrivate: BigInteger,
    )

    // ---- routing ----

    override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse {
        calls.add("GET" to url)
        return when (url) {
            IdsBagFetcher.IDS_BAG_URL -> bag(headers)
            certUrl -> validationCertStep(headers)
            "https://gsa.apple.com/auth/verify/trusteddevice" -> trustedDeviceTrigger()
            "https://gsa.apple.com/grandslam/GsService2/validate" -> validate(headers)
            else -> throw IllegalStateException("dry-run fake: unexpected GET $url")
        }
    }

    override suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        calls.add("POST" to url)
        return when (url) {
            initUrl -> initialize(headers, body, contentType)
            adiStartUrl -> adiStart(headers, body, contentType)
            adiFinishUrl -> adiFinish(headers, body, contentType)
            AlbertActivator.DEFAULT_URL -> albert(headers, body, contentType)
            "https://gsa.apple.com/grandslam/GsService2" -> grandslam(body)
            GsaDelegateLoginClient.SIGNIN_ENDPOINT -> delegateSignIn(headers, body)
            authenticateUrl -> authenticate(headers, body, contentType)
            registerUrl -> register(headers, body, contentType)
            else -> throw IllegalStateException("dry-run fake: unexpected POST $url")
        }
    }

    override suspend fun put(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse = throw IllegalStateException("dry-run fake: unexpected PUT $url")

    // ---- bag + validation exchange (§1.1 steps 1–2, §1.2 bag) ----

    private fun bag(headers: Map<String, String>): IdsHttpResponse {
        require(headers.isEmpty()) { "bag GET is unauthenticated (§1.2 [CAP-BAG]) — got ${headers.keys}" }
        bagFetches++
        val inner = XmlPlist.encode(
            linkedMapOf<String, Any?>(
                ValidationBagKeys.CERT to certUrl,
                ValidationBagKeys.INITIALIZE to initUrl,
                IdsAuthenticator.BAG_KEY_DS_ID to authenticateUrl,
                IdsRegistrar.BAG_KEY to registerUrl,
            ),
        )
        // The recorded IDS bag shape: outer plist with an embedded `bag` plist data (§1.2).
        return plist(200, linkedMapOf("signature" to "fixture", "bag" to inner))
    }

    private fun validationCertStep(headers: Map<String, String>): IdsHttpResponse {
        require(headers.isEmpty()) { "step-1 GET carries no recorded headers (§1.1) — got ${headers.keys}" }
        validationCertFetches++
        return plist(200, linkedMapOf<String, Any?>("cert" to validationCert))
    }

    private fun initialize(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        // §1.1 step 2: body only — NO anisette, NO authentication headers.
        require(headers.isEmpty()) { "step-2 POST is body-only (§1.1) — got ${headers.keys}" }
        require(contentType == ValidationCertClient.CONTENT_TYPE) {
            "step-2 content type '$contentType' (§1.1: the recorded client sets NO content-type)"
        }
        val request = Plist.parse(body) as? Map<*, *>
        require(request != null && request.keys == setOf("session-info-request")) {
            "step-2 body is not the single-key session-info-request plist (§1.1)"
        }
        require(request["session-info-request"] is ByteArray) { "step-2 session-info-request is not data (§1.1)" }
        initializeCount++
        return plist(200, linkedMapOf<String, Any?>("session-info" to sessionInfoPoint))
    }

    // ---- ADI provisioning (§1.1; paths/keys/encodings unrecorded — C6, structural only) ----

    private fun adiStart(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        adiStartCount++
        require(body.decodeToString().contains("start")) { "ADI start request body does not carry its phase marker" }
        return plist(200, linkedMapOf<String, Any?>("session" to adiSessionBytes))
    }

    private fun adiFinish(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        adiFinishCount++
        require(body.decodeToString().contains("finish")) { "ADI finish request body does not carry its phase marker" }
        // Machine tokens: field names are unrecorded (C6) — the machine identifier rides here.
        return plist(
            200,
            linkedMapOf<String, Any?>(
                "machine-token" to ByteArray(16) { (it + 0x21).toByte() },
                "machine-identifier" to machineIdentifier,
            ),
        )
    }

    // ---- Albert activation (§1.2) ----

    private fun albert(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        require(contentType == AlbertActivator.CONTENT_TYPE) { "activation post is not form-urlencoded (§1.2)" }
        require(headers.isEmpty()) { "activation post carries no recorded headers (§1.2) — got ${headers.keys}" }
        val text = body.decodeToString()
        require(text.startsWith(AlbertActivator.FORM_KEY + "=")) { "activation post has more than the one form key (§1.2)" }
        val formValue = java.net.URLDecoder.decode(text.substringAfter('='), Charsets.UTF_8)
        val outer = Plist.parse(formValue.toByteArray()) as? Map<*, *>
            ?: throw IllegalStateException("activation form value is not a plist (§1.2)")
        require(outer.keys == setOf("ActivationInfoComplete", "ActivationInfoXML", "FairPlayCertChain", "FairPlaySignature")) {
            "activation-info outer keys are ${outer.keys} (§1.2)"
        }
        require(outer["ActivationInfoComplete"] == true) { "ActivationInfoComplete is not true (§1.2)" }

        val activationInfoXml = (outer["ActivationInfoXML"] as String).toByteArray(Charsets.UTF_8)
        val nested = Plist.parse(activationInfoXml) as Map<*, *>
        require(nested.keys == setOf(
            "ActivationRandomness", "ActivationState", "BuildVersion", "DeviceCertRequest",
            "DeviceClass", "ProductType", "ProductVersion", "SerialNumber", "UniqueDeviceID",
        )) { "ActivationInfoXML keys are ${nested.keys} (§1.2)" }
        require(nested["ActivationState"] == "Unactivated") { "ActivationState must be Unactivated (§1.2)" }
        require(nested["DeviceClass"] == "MacOS") { "DeviceClass must be MacOS (§1.2)" }
        val csrPem = nested["DeviceCertRequest"] as String
        require(csrPem.contains(Pem.CSR_TYPE)) { "DeviceCertRequest is not a PEM CSR (§1.2)" }
        val csrValues = csrSubjectValues(Pem.decode(csrPem, Pem.CSR_TYPE))
        require(csrValues == listOf(AlbertCsr.COMMON_NAME, AlbertCsr.ORGANIZATIONAL_UNIT, AlbertCsr.ORGANIZATION)) {
            "DeviceCertRequest subject is $csrValues (§1.2: Client Push Certificate / iPhone / Apple Inc.)"
        }

        // §1.2: the FairPlay signature is SHA-1 RSA PKCS#1v15 over the exact ActivationInfoXML
        // bytes, verifying against the FairPlayCertChain's public key.
        val verifier = java.security.Signature.getInstance(BundledFairPlaySigner.SIGNATURE_ALGORITHM)
        verifier.initVerify(BundledFairPlaySigner.certificatePublicKey(outer["FairPlayCertChain"] as ByteArray))
        verifier.update(activationInfoXml)
        require(verifier.verify(outer["FairPlaySignature"] as ByteArray)) {
            "FairPlaySignature does not verify against FairPlayCertChain's public key (§1.2)"
        }
        albertActivations++
        return IdsHttpResponse(200, emptyMap(), protocolWrap(
            XmlPlist.encode(
                linkedMapOf<String, Any?>(
                    "device-activation" to linkedMapOf<String, Any?>(
                        "activation-record" to linkedMapOf<String, Any?>("DeviceCertificate" to deviceCertPem),
                    ),
                    "ack-received" to true,
                    "show-settings" to false,
                ),
            ),
        ))
    }

    /** The response's outer `<Protocol>` block (§1.2). */
    private fun protocolWrap(plist: ByteArray): ByteArray {
        val inner = plist.decodeToString().substring(plist.decodeToString().indexOf("<plist"))
        return """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Protocol>
$inner</Protocol>""".toByteArray()
    }

    // ---- GSA SRP login (§1.5) ----

    private fun grandslam(body: ByteArray): IdsHttpResponse {
        val request = (XmlPlist.decode(body) as Map<*, *>)["Request"] as Map<*, *>
        require(request["cpd"] is Map<*, *>) { "GSA request carries no cpd dict (§1.5)" }
        return if (request["o"] == "init") init(request) else complete(request)
    }

    private fun init(request: Map<*, *>): IdsHttpResponse {
        gsaInitCount++
        val aPublic = request["A2k"] as ByteArray
        val passwordKey = GsaSrpPasswordKey.derive(passwordHash, salt, 1000, "s2k")
        // §1.5 identity-hash quirk: SHA-256 over EMPTY username, i.e. just ':' ‖ password key.
        val x = BigInteger(1, sha256(salt + sha256(byteArrayOf(':'.code.toByte()) + passwordKey)))
        val verifier = group.generator.modPow(x, group.n)
        val serverPrivate = BigInteger(1, ByteArray(group.byteLength - 1).also { SecureRandom().nextBytes(it) })
        val k = BigInteger(1, sha256(group.prime + padGenerator()))
        val serverPublic = k.multiply(verifier).add(group.generator.modPow(serverPrivate, group.n)).mod(group.n)
        session = Session(aPublic, minimalBytes(serverPublic), verifier, serverPrivate)
        return plist(
            200,
            mapOf(
                "Response" to linkedMapOf<String, Any?>(
                    "s" to salt,
                    "B" to minimalBytes(serverPublic),
                    "i" to 1000L,
                    "c" to "challenge",
                    "sp" to "s2k",
                    "Status" to linkedMapOf<String, Any?>("ec" to 0L, "em" to ""),
                ),
            ),
        )
    }

    private fun complete(request: Map<*, *>): IdsHttpResponse {
        gsaCompleteCount++
        val s = session ?: throw IllegalStateException("GSA complete before init")
        val m1 = request["M1"] as ByteArray
        val u = BigInteger(1, sha256(s.aPublic + s.serverPublic))
        val premaster = BigInteger(1, s.aPublic).multiply(s.verifier.modPow(u, group.n))
            .mod(group.n).modPow(s.serverPrivate, group.n)
        val serverK = sha256(minimalBytes(premaster))
        val expectedM1 = sha256(
            xor(sha256(group.prime), sha256(padGenerator())) +
                sha256((request["u"] as String).toByteArray()) + salt + s.aPublic + s.serverPublic + serverK,
        )
        require(expectedM1.contentEquals(m1)) { "dry-run fake: client M1 did not verify (§1.5 SRP)" }
        val computedM2 = sha256(s.aPublic + m1 + serverK)
        val response = linkedMapOf<String, Any?>(
            "M2" to computedM2,
            "spd" to encryptSpd(serverK),
            "Status" to linkedMapOf<String, Any?>("ec" to 0L),
        )
        if (gsaCompleteCount == 1) response["au"] = GsaStatus.AU_TRUSTED_DEVICE
        petCounter++
        return IdsHttpResponse(
            200,
            mapOf("X-Apple-PE-Token" to base64("com.apple.gs.idms.pet:pet-$petCounter")),
            XmlPlist.encode(mapOf("Response" to response)),
        )
    }

    private fun encryptSpd(serverK: ByteArray): ByteArray {
        val plain = XmlPlist.encode(
            linkedMapOf<String, Any?>(
                "adsid" to adsid,
                "DsPrsId" to 123456789L,
                "GsIdmsToken" to "idms-token-1",
                "t" to emptyMap<String, Any?>(),
            ),
        )
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(GsaSpdDecryptor.key(serverK), "AES"),
            IvParameterSpec(GsaSpdDecryptor.iv(serverK)),
        )
        return cipher.doFinal(plain)
    }

    private fun trustedDeviceTrigger(): IdsHttpResponse {
        trustedDeviceTriggers++
        return IdsHttpResponse(200, emptyMap(), ByteArray(0))
    }

    private fun validate(headers: Map<String, String>): IdsHttpResponse {
        validateSecurityCode = headers["security-code"]
        require(validateSecurityCode == securityCode) {
            "trusted-device validate carried code '$validateSecurityCode' — expected the fixture code (§1.5)"
        }
        val identityToken = requireNotNull(headers["X-Apple-Identity-Token"]) {
            "trusted-device validate carried no X-Apple-Identity-Token (§1.5: all 2FA requests carry base64 adsid:GsIdmsToken)"
        }
        val decoded = String(java.util.Base64.getDecoder().decode(identityToken), Charsets.UTF_8)
        require(decoded == "$adsid:idms-token-1") {
            "validate identity token form mismatch (§1.5: base64 adsid:GsIdmsToken)"
        }
        validateCount++
        petCounter++
        return IdsHttpResponse(
            200,
            mapOf("X-Apple-PE-Token" to base64("com.apple.gs.idms.pet:pet-$petCounter")),
            ByteArray(0),
        )
    }

    // ---- iCloud delegate sign-in (§1.5) ----

    private fun delegateSignIn(headers: Map<String, String>, body: ByteArray): IdsHttpResponse {
        val basic = headers["Authorization"] ?: throw IllegalStateException("sign-in has no Basic auth (§1.5)")
        val decoded = String(Base64.getDecoder().decode(basic.removePrefix("Basic ")), Charsets.UTF_8)
        delegateUsername = decoded.substringBefore(":")
        delegatePet = decoded.substringAfter(":")

        val blob = expectedValidationBlob
            ?: throw IllegalStateException("sign-in hit before the test wired expectedValidationBlob")
        require(headers["X-Mme-Nas-Qualify"] == base64Bytes(blob)) {
            "X-Mme-Nas-Qualify is not the base64 of the step-3 validation blob (§1.1/§1.5)"
        }
        require(headers["X-Apple-ADSID"] == adsid) { "sign-in X-Apple-ADSID mismatch (§1.5)" }
        // The full anisette set rides the sign-in (§1.5): base OTP/machine-id headers + the
        // macOS hardware headers.
        require(headers.containsKey("X-Apple-I-MD") && headers.containsKey("X-Apple-I-MD-M")) {
            "sign-in carries no anisette OTP/machine-id headers (§1.1/§1.5)"
        }
        require(headers.containsKey("X-Apple-I-MLB") && headers.containsKey("X-Apple-I-SRL-NO")) {
            "sign-in carries no macOS hardware headers (§1.1/§1.5)"
        }
        require(headers["X-Mme-Client-Info"]?.startsWith("<") == true) {
            "sign-in X-Mme-Client-Info is not the recorded bracketed form (§1.5)"
        }
        require(headers["User-Agent"] == GsaDelegateLoginClient.SIGNIN_USER_AGENT) {
            "sign-in User-Agent is not the recorded iCloudHelper form (§1.5)"
        }

        val request = Plist.parse(body) as? Map<*, *> ?: throw IllegalStateException("sign-in body is not a plist (§1.5)")
        val delegates = request["delegates"] as? Map<*, *> ?: throw IllegalStateException("sign-in body has no delegates dict (§1.5)")
        val idsDelegate = delegates["com.apple.private.ids"] as? Map<*, *>
        require(idsDelegate != null && idsDelegate["protocol-version"] == "4") {
            "sign-in delegates miss com.apple.private.ids {protocol-version: 4} (§1.5)"
        }
        require(delegates.containsKey("com.apple.mobileme")) { "sign-in delegates miss com.apple.mobileme (§1.5)" }
        require(request["protocolVersion"] == "1.0") { "sign-in protocolVersion must be 1.0 (§1.5)" }
        val userInfo = request["userInfo"] as? Map<*, *>
        require(userInfo != null && userInfo.keys == setOf("clientId", "language", "timezone")) {
            "sign-in userInfo shape wrong (§1.5)"
        }
        require((userInfo["language"] as String) == "en-US") { "sign-in userInfo.language must be en-US (§1.5)" }

        signInCount++
        return plist(
            200,
            linkedMapOf(
                "status" to 0L,
                "delegates" to linkedMapOf<String, Any?>(
                    "com.apple.private.ids" to linkedMapOf<String, Any?>(
                        "status" to 0L,
                        "statusMessage" to "OK",
                        "serviceData" to linkedMapOf<String, Any?>(
                            "auth-token" to authToken,
                            "profile-id" to profileId,
                        ),
                    ),
                    "com.apple.mobileme" to linkedMapOf<String, Any?>(
                        "status" to 0L,
                        "serviceData" to linkedMapOf<String, Any?>("mmeAuthToken" to "mme-token-fixture"),
                    ),
                ),
            ),
        )
    }

    // ---- authenticate (§1.2) ----

    private fun authenticate(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        // §1.2: ONLY user-agent and x-protocol-version, plus content-encoding: gzip.
        require(headers.keys == setOf("user-agent", "x-protocol-version", "content-encoding")) {
            "authenticate header set is ${headers.keys} (§1.2: user-agent, x-protocol-version, content-encoding only)"
        }
        require(headers["content-encoding"] == "gzip") { "authenticate body is not gzipped (§1.2)" }
        val request = Plist.parse(gunzip(body)) as? Map<*, *>
            ?: throw IllegalStateException("authenticate body is not a plist (§1.2)")
        require(request.keys == setOf("authentication-data", "csr", "realm-user-id")) {
            "authenticate body keys are ${request.keys} (§1.2)"
        }
        require(request["authentication-data"] == mapOf("auth-token" to authToken)) {
            "authenticate authentication-data is not {auth-token: …} (§1.2/§1.5)"
        }
        require(request["realm-user-id"] == profileId) { "authenticate realm-user-id mismatch (§1.2)" }
        val csr = expectedCsrDer
            ?: throw IllegalStateException("authenticate hit before the test wired expectedCsrDer")
        require((request["csr"] as ByteArray).contentEquals(csr)) { "authenticate CSR bytes mismatch (§1.2)" }
        authenticateCount++
        return plist(200, linkedMapOf<String, Any?>("status" to 0L, "cert" to identityCertDer))
    }

    // ---- register (§1.4) ----

    private fun register(headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
        require(contentType == IdsRegistrar.CONTENT_TYPE) { "register content type is not the recorded plist type (§1.4)" }
        require(headers.containsKey("x-push-nonce") && headers.containsKey("x-push-cert") && headers.containsKey("x-push-sig")) {
            "register carries no push signature set (§1.4)"
        }
        require(headers.containsKey("x-push-token")) { "register carries no x-push-token (§1.4)" }
        require(headers.containsKey("x-auth-user-id-0") && headers.containsKey("x-auth-nonce-0") &&
            headers.containsKey("x-auth-cert-0") && headers.containsKey("x-auth-sig-0")) {
            "register carries no indexed per-user auth signature set (§1.4)"
        }
        require(headers["x-auth-user-id-0"] == profileId) { "x-auth-user-id-0 is not the profile id (§1.4)" }

        val request = Plist.parse(body) as? Map<*, *> ?: throw IllegalStateException("register body is not a plist (§1.4)")
        // §1.4: exactly the eight recorded top-level keys, none beyond.
        require(request.keys == setOf(
            "device-name", "hardware-version", "language", "os-version", "software-version",
            "private-device-data", "services", "validation-data",
        )) { "register top-level keys are ${request.keys} (§1.4)" }
        val blob = expectedValidationBlob
            ?: throw IllegalStateException("register hit before the test wired expectedValidationBlob")
        require((request["validation-data"] as ByteArray).contentEquals(blob)) {
            "register validation-data is not the step-3 blob verbatim (§1.1/§1.4)"
        }
        val pdd = request["private-device-data"] as? Map<*, *>
        require(pdd != null && pdd.keys.size == 14 && (pdd["dt"] as Long) == 1L && (pdd["v"] as String) == "1") {
            "private-device-data shape wrong (§1.4)"
        }
        val services = request["services"] as? List<*>
        val service = services?.singleOrNull() as? Map<*, *>
        require(service != null && service["service"] == RegisterService.MADRID) {
            "register services must carry com.apple.madrid (§1.4)"
        }
        require(service["sub-services"] == RegisterService.SUB_SERVICES) { "register sub-services mismatch (§1.4)" }
        val capability = (service["capabilities"] as List<*>).single() as Map<*, *>
        require(capability == mapOf("flags" to 17L, "name" to "Messenger", "version" to 1L)) {
            "register capability record mismatch (§1.4)"
        }
        val user = (service["users"] as List<*>).single() as Map<*, *>
        require(user["user-id"] == profileId) { "register user-id mismatch (§1.4)" }
        require(user["uris"] == listOf(mapOf("uri" to registeredUri))) {
            "register uris are not the server-echoed handle list (§1.4)"
        }

        registerCount++
        registerCalls.add(RegisterCall(headers, body))
        return plist(
            200,
            linkedMapOf(
                "status" to 0L,
                "message" to "ok",
                "retry-interval" to 600L,
                "services" to listOf(
                    linkedMapOf<String, Any?>(
                        "service" to RegisterService.MADRID,
                        "status" to 0L,
                        "users" to listOf(
                            linkedMapOf<String, Any?>(
                                "user-id" to profileId,
                                "status" to 0L,
                                "next-hbi" to 86400L,
                                "cert" to identityCertDer,
                                "uris" to listOf(linkedMapOf<String, Any?>("uri" to registeredUri, "status" to 0L)),
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    // ---- helpers ----

    private fun plist(status: Int, dict: Map<String, Any?>) = IdsHttpResponse(200, emptyMap(), XmlPlist.encode(dict))

    private fun base64(text: String) = Base64.getEncoder().encodeToString(text.toByteArray(Charsets.UTF_8))

    private fun base64Bytes(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)

    private fun gunzip(bytes: ByteArray): ByteArray =
        java.util.zip.GZIPInputStream(bytes.inputStream()).use { it.readBytes() }

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun xor(a: ByteArray, b: ByteArray): ByteArray =
        ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }

    private fun padGenerator(): ByteArray = ByteArray(group.byteLength - 1) + 0x02.toByte()

    private fun minimalBytes(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        return if (signed.size > 1 && signed[0] == 0.toByte()) signed.copyOfRange(1, signed.size) else signed
    }

    private fun resourceDer(pemResource: String): ByteArray {
        val pem = javaClass.getResourceAsStream(pemResource)!!.bufferedReader().readText()
        val base64Body = pem.substringAfter("-----BEGIN CERTIFICATE-----")
            .substringBefore("-----END CERTIFICATE-----")
        return java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(java.io.ByteArrayInputStream(Base64.getMimeDecoder().decode(base64Body)))
            .encoded
    }
}
