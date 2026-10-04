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
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The §1.5 chain end to end against an in-test scripted GSA server (a second independent
 * implementation of the spec's server-side formulas): login → M2 verification → spd → PET
 * persistence, both 2FA variants with the recorded "run the SRP login a second time" behavior,
 * re-login-on-expiry, and the delegate-login handoff to the §1.2 authenticate path.
 */
class GsaLoginChainTest {

    private val password = "correct horse battery staple"
    private val passwordHash = MessageDigest.getInstance("SHA-256").digest(password.toByteArray())
    private val username = "user@example.com"

    private val cpd = GsaCpd(
        anisette = mapOf(
            "X-Apple-I-Client-Time" to "2026-09-11T12:00:00Z",
            "X-Apple-I-MD" to "otp",
            "X-Apple-I-MD-RINFO" to "17106176",
            "X-Apple-I-MD-M" to "machine-id",
            "X-Mme-Device-Id" to "device-id",
        ),
        keychainIdentifier = ByteArray(16) { it.toByte() },
    )

    private fun chain(
        http: IdsHttp,
        store: GsaCredentialStore? = null,
        now: () -> Long = { 1_770_000_000_000L },
    ) = GsaLoginChain(
        http = http,
        cpd = { cpd },
        credentialStore = store,
        twoFactorHeaders = {
            GsaTwoFactorHeaders.of(
                cpd,
                device = GsaHeaderConfig(
                    hardwareModel = "iMac13,1",
                    osName = "macOS",
                    osVersion = "13.6.4",
                    osBuild = "22G513",
                ),
                userAgent = "ua",
            )
        },
        clock = now,
    )

    @Test
    fun `login runs init and complete, decrypts spd, persists the credentials`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = null)
        val store = RecordingStore()
        val result = chain(server, store).login(username, password)

        val authenticated = result as GsaLoginResult.Authenticated
        assertEquals("adsid-1", authenticated.spd?.adsid)
        assertEquals("idms-token-1", authenticated.spd!!.gsIdmsToken)
        assertEquals("pet-1", authenticated.pet?.token)
        assertEquals(1, server.initCount)
        assertEquals(1, server.completeCount)
        assertEquals(username, store.saved!!.username)
        assertTrue(store.saved!!.passwordHash.contentEquals(passwordHash))
        assertEquals("adsid-1", store.saved!!.adsid)
        assertEquals("pet-1", store.saved!!.petToken)
        // No PET trailer → the recorded 300 s default (§1.5).
        assertEquals(1_770_000_000_000L + 300_000, store.saved!!.petExpiresAtEpochMs)
    }

    @Test
    fun `server M2 proof mismatch fails loudly`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = null, corruptM2 = true)
        assertFailsWith<GsaLoginException> { chain(server).login(username, password) }
        assertTrue(server.completeCount == 1)
    }

    @Test
    fun `sms secondary auth resolves then re-runs the SRP login`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = GsaStatus.AU_SECONDARY_AUTH)
        val store = RecordingStore()
        val chain = chain(server, store)

        val required = chain.login(username, password) as GsaLoginResult.SecondaryAuthRequired
        assertEquals(GsaStatus.AU_SECONDARY_AUTH, required.variant)
        // The identity token comes from the spd that arrived with the 2FA-required response.
        assertEquals(gsaIdentityToken("adsid-1", "idms-token-1"), required.identityToken)
        assertNull(store.saved, "nothing persisted before 2FA completes")

        server.secondaryAuth = null
        val result = chain.completeSecondaryAuth(
            username = username,
            passwordHash = passwordHash,
            variant = GsaStatus.AU_SECONDARY_AUTH,
            identityToken = required.identityToken!!,
            securityCode = "123456",
            phoneNumberId = "7",
        )
        assertTrue(result is GsaLoginResult.Authenticated)
        assertEquals(2, server.initCount, "§1.5: the SRP login runs a second time after 2FA")
        assertTrue(server.smsRequested && server.smsVerified)
        // pet-1 rode the 2FA-required complete, pet-2 the SMS verification response, pet-3 the re-login.
        assertEquals("pet-3", store.saved!!.petToken)
    }

    @Test
    fun `trusted-device secondary auth pushes on the chain then validates with the security-code header`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = GsaStatus.AU_TRUSTED_DEVICE)
        val chain = chain(server)

        val required = chain.login(username, password) as GsaLoginResult.SecondaryAuthRequired
        assertEquals(GsaStatus.AU_TRUSTED_DEVICE, required.variant)

        // The push is the caller's job (production: right after SecondaryAuthRequired);
        // completeSecondaryAuth validates only — a second trigger invalidates the code.
        server.secondaryAuth = null
        chain.triggerTrustedDevicePush(GsaStatus.AU_TRUSTED_DEVICE, required.identityToken!!)
        val result = chain.completeSecondaryAuth(
            username = username,
            passwordHash = passwordHash,
            variant = GsaStatus.AU_TRUSTED_DEVICE,
            identityToken = required.identityToken!!,
            securityCode = "987654",
        )
        assertTrue(result is GsaLoginResult.Authenticated)
        assertEquals("987654", server.validateSecurityCode)
        assertTrue(server.trustedDeviceTriggered)
    }

    @Test
    fun `unknown secondary-auth variant fails loudly`() {
        val server = FakeGsaServer(passwordHash, secondaryAuth = null)
        val exception = assertFailsWith<GsaLoginException> {
            runBlocking {
                chain(server).completeSecondaryAuth(
                    username, passwordHash, variant = "circlePake", identityToken = "x", securityCode = "1",
                )
            }
        }
        assertTrue(exception.message!!.contains("circlePake"))
    }

    @Test
    fun `petToken serves the stored pet while fresh and re-logins once expired`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = null)
        val store = RecordingStore()
        val chain = chain(server, store)

        // Nothing persisted yet.
        assertNull(chain.petToken())

        chain.login(username, password)
        val fresh = 1_770_000_000_000L + 100_000
        assertEquals("pet-1", chain.petToken(fresh))
        assertEquals(1, server.initCount, "fresh PET → no network")

        // §1.5: expired → silently re-run the SRP login with the persisted password hash.
        assertEquals("pet-2", chain.petToken(fresh + 300_000))
        assertEquals(2, server.initCount)
    }

    @Test
    fun `delegate login yields the ids credentials and hands off to the authenticate path`() = runBlocking {
        val server = FakeGsaServer(passwordHash, secondaryAuth = null)
        val chain = chain(server)
        val authenticated = chain.login(username, password) as GsaLoginResult.Authenticated

        val credentials = chain.idsDelegateCredentials(
            username = username,
            pet = authenticated.pet!!.token,
            adsid = authenticated.spd!!.adsid!!,
            validationData = byteArrayOf(1, 2, 3),
            timezone = "Europe/Berlin",
            clientInfo = "macOS;13.5;22G74",
            anisette = emptyMap(),
        )
        assertEquals("ids-auth-token", credentials.authToken)
        assertEquals("profile-1", credentials.profileId)
        assertTrue(server.delegateSignInSeen)
        assertEquals("pet-1", server.delegatePet) // Basic username:PET rode the sign-in
        assertEquals(username, server.delegateUsername)

        // The natural next step: the §1.2 authenticate exchange consumes them verbatim.
        val authHttp = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(
                    200,
                    emptyMap(),
                    XmlPlist.encode(mapOf("status" to 0L, "cert" to byteArrayOf(1, 1))),
                ),
            ),
        )
        val bag = Bag(mapOf("id-authenticate-ds-id" to "https://identity.example.com/authenticateDS"))
        val response = chain.authenticateIds(
            credentials = credentials,
            bagKey = IdsAuthenticator.BAG_KEY_DS_ID,
            csrDer = byteArrayOf(9),
            authenticator = IdsAuthenticator(authHttp, bag, protocolVersion = "1640", userAgent = "ua"),
        )
        assertEquals(0, response.status)
        val requestBody = gunzip(authHttp.calls.single().body)
        val body = XmlPlist.decode(requestBody) as Map<*, *>
        assertEquals("profile-1", body["realm-user-id"])
        assertEquals(
            mapOf("auth-token" to "ids-auth-token"),
            body["authentication-data"],
        )
    }

    /** The §1.2 authenticate path gzips its request body — undo it for the assertion. */
    private fun gunzip(bytes: ByteArray): ByteArray =
        java.util.zip.GZIPInputStream(bytes.inputStream()).use { it.readBytes() }
}

/** Records what the orchestrator persists (stand-in for the Room-backed adapter). */
private class RecordingStore : GsaCredentialStore {
    var saved: GsaPersistedCredentials? = null
    override suspend fun load(): GsaPersistedCredentials? = saved
    override suspend fun save(credentials: GsaPersistedCredentials) {
        saved = credentials
    }
}

/**
 * A scripted GSA server: an independent test-side implementation of the §1.5 server half
 * (init/complete SRP with the identity-hash quirk, spd encryption, 2FA endpoints, delegate
 * sign-in). Its K is derived from the client's A exactly as the spec's formulas dictate.
 */
private class FakeGsaServer(
    private val passwordHash: ByteArray,
    var secondaryAuth: String?,
    private val corruptM2: Boolean = false,
) : IdsHttp {

    private val group = GsaSrpGroup

    var initCount = 0
    var completeCount = 0
    var smsRequested = false
    var smsVerified = false
    var trustedDeviceTriggered = false
    var validateSecurityCode: String? = null
    var delegateSignInSeen = false
    var delegatePet: String? = null
    var delegateUsername: String? = null

    private val salt = ByteArray(16) { it.toByte() }
    private val random = SecureRandom()
    private var session: Session? = null
    private var petCounter = 0

    private class Session(
        val aPublic: ByteArray,
        val serverPublic: ByteArray,
        val verifier: BigInteger,
        val serverPrivate: BigInteger,
    )

    override suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse = when {
        url.endsWith("/GsService2") -> grandslam(body)
        url.endsWith("/setup/signin/v2/login") -> delegateSignIn(headers)
        url.endsWith("/verify/phone/securitycode") -> {
            smsVerified = true
            tokensResponse()
        }
        else -> throw IllegalStateException("unexpected POST $url")
    }

    override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse = when {
        url.endsWith("/auth") && !url.contains("verify") ->
            IdsHttpResponse(
                200,
                emptyMap(),
                """{"trustedPhoneNumbers":[{"numberWithDialCode":"+15550001111","lastTwoDigits":"11",
                   "pushMode":false,"id":7}]}""".toByteArray(),
            )
        url.endsWith("/verify/trusteddevice") -> {
            trustedDeviceTriggered = true
            IdsHttpResponse(200, emptyMap(), ByteArray(0))
        }
        url.endsWith("/GsService2/validate") -> {
            validateSecurityCode = headers["security-code"]
            tokensResponse()
        }
        else -> throw IllegalStateException("unexpected GET $url")
    }

    override suspend fun put(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        require(url.endsWith("/verify/phone")) { "unexpected PUT $url" }
        smsRequested = true
        return IdsHttpResponse(200, emptyMap(), ByteArray(0))
    }

    private fun grandslam(body: ByteArray): IdsHttpResponse {
        val request = (XmlPlist.decode(body) as Map<*, *>)["Request"] as Map<*, *>
        return if (request["o"] == "init") init(request) else complete(request)
    }

    private fun init(request: Map<*, *>): IdsHttpResponse {
        initCount++
        val aPublic = request["A2k"] as ByteArray
        val passwordKey = GsaSrpPasswordKey.derive(passwordHash, salt, 1000, "s2k")
        val x = BigInteger(1, sha256(salt + sha256(byteArrayOf(':'.code.toByte()) + passwordKey)))
        val verifier = group.generator.modPow(x, group.n)
        val serverPrivate = BigInteger(1, ByteArray(group.byteLength - 1).also { random.nextBytes(it) })
        val k = BigInteger(1, sha256(group.prime + padGenerator()))
        val serverPublic = k.multiply(verifier).add(group.generator.modPow(serverPrivate, group.n)).mod(group.n)
        session = Session(aPublic, minimalBytes(serverPublic), verifier, serverPrivate)
        return plistResponse(
            linkedMapOf<String, Any?>(
                "s" to salt,
                "B" to minimalBytes(serverPublic),
                "i" to 1000L,
                "c" to "challenge",
                "sp" to "s2k",
                "Status" to linkedMapOf<String, Any?>("ec" to 0L, "em" to ""),
            ),
        )
    }

    private fun complete(request: Map<*, *>): IdsHttpResponse {
        completeCount++
        val s = session ?: throw IllegalStateException("complete before init")
        val m1 = request["M1"] as ByteArray
        val u = BigInteger(1, sha256(s.aPublic + s.serverPublic))
        val premaster = BigInteger(1, s.aPublic).multiply(s.verifier.modPow(u, group.n))
            .mod(group.n).modPow(s.serverPrivate, group.n)
        val serverK = sha256(minimalBytes(premaster))
        val expectedM1 = sha256(
            xor(sha256(group.prime), sha256(padGenerator())) +
                sha256((request["u"] as String).toByteArray()) + salt + s.aPublic + s.serverPublic + serverK,
        )
        require(expectedM1.contentEquals(m1)) { "scripted server: client M1 did not verify" }
        val computedM2 = sha256(s.aPublic + m1 + serverK)
        val m2 = if (corruptM2) {
            computedM2.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        } else {
            computedM2
        }
        val status = linkedMapOf<String, Any?>("ec" to 0L)
        secondaryAuth?.let { status["au"] = it }
        val response = linkedMapOf<String, Any?>(
            "M2" to m2,
            "spd" to encryptSpd(serverK),
            "Status" to status,
        )
        petCounter++
        return IdsHttpResponse(
            200,
            mapOf(
                "X-Apple-PE-Token" to java.util.Base64.getEncoder()
                    .encodeToString("com.apple.gs.idms.pet:pet-$petCounter".toByteArray()),
            ),
            XmlPlist.encode(mapOf("Response" to response)),
        )
    }

    private fun encryptSpd(serverK: ByteArray): ByteArray {
        val plain = XmlPlist.encode(
            linkedMapOf<String, Any?>(
                "adsid" to "adsid-1",
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

    private fun tokensResponse(): IdsHttpResponse {
        petCounter++
        return IdsHttpResponse(
            200,
            mapOf(
                "X-Apple-PE-Token" to java.util.Base64.getEncoder()
                    .encodeToString("com.apple.gs.idms.pet:pet-$petCounter".toByteArray()),
            ),
            ByteArray(0),
        )
    }

    private fun delegateSignIn(headers: Map<String, String>): IdsHttpResponse {
        delegateSignInSeen = true
        val basic = String(
            java.util.Base64.getDecoder().decode(headers["Authorization"]!!.removePrefix("Basic ")),
        )
        delegateUsername = basic.substringBefore(":")
        delegatePet = basic.substringAfter(":")
        return IdsHttpResponse(
            200,
            emptyMap(),
            XmlPlist.encode(
                mapOf(
                    "status" to 0L,
                    "delegates" to linkedMapOf(
                        "com.apple.private.ids" to linkedMapOf<String, Any?>(
                            "status" to 0L,
                            "serviceData" to linkedMapOf<String, Any?>(
                                "auth-token" to "ids-auth-token",
                                "profile-id" to "profile-1",
                            ),
                        ),
                    ),
                ),
            ),
        )
    }

    private fun plistResponse(response: Map<String, Any?>) =
        IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("Response" to response)))

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun xor(a: ByteArray, b: ByteArray): ByteArray =
        ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }

    private fun padGenerator(): ByteArray = ByteArray(group.byteLength - 1) + 0x02.toByte()

    private fun minimalBytes(value: BigInteger): ByteArray {
        val signed = value.toByteArray()
        return if (signed.size > 1 && signed[0] == 0.toByte()) signed.copyOfRange(1, signed.size) else signed
    }
}
