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
import dev.fenn.imessage.ids.gunzipIfNeeded
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
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

class IdsActivationTest {

    private val registerUrl = "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register"
    private val authUrl = "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS"
    private val phoneAuthUrl =
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/authenticatePhoneNumber"
    private val pushToken = ByteArray(32) { it.toByte() }
    private val pushCert = byteArrayOf(0x30, 0x82.toByte(), 0x02, 0x00)
    private val authCert = byteArrayOf(0x30, 0x82.toByte(), 0x03, 0x00)

    private fun config() = RegisterConfig(
        pushToken = pushToken,
        pushKey = PUSH.private,
        pushCertificateDer = pushCert,
        protocolVersion = "1660",
        userAgent = "com.apple.invitation-registration [Test,1,1,Test]",
    )

    private fun user(userId: String = "user-1") = RegisterUser(
        userId = userId,
        uris = listOf(mapOf("uri" to "tel:+15557654321")),
        tag = null,
        authKey = AUTH.private,
        authCertificateDer = authCert,
        clientData = mapOf("client-data-version" to 2L),
        ktLoggableData = null,
    )

    private fun body(user: RegisterUser = user()) = RegisterBody(
        deviceName = "LP3",
        hardwareVersion = "h1",
        language = "en",
        osVersion = "14.6.1",
        softwareVersion = "1.0",
        privateDeviceData = PrivateDeviceData(
            osBuild = "24G84",
            platformName = "Mac15,12",
            osVersion = "14.6.1",
            deviceUuid = "abcd-ef",
            appleEpochSeconds = 800_000_000L,
        ),
        services = listOf(RegisterService(RegisterService.MADRID, users = listOf(user))),
        validationData = byteArrayOf(1, 2, 3),
    )

    private fun registrar(http: IdsHttp, refreshMarker: String? = null) =
        IdsRegistrar(http, Bag(mapOf("id-register" to registerUrl)), config(), refreshMarker)

    @Test
    fun registerIsSignedForThePushKeyAndEachUser() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        registrar(http).register(body())

        val call = http.calls.single()
        assertEquals(registerUrl, call.url)
        assertEquals(IdsRegistrar.CONTENT_TYPE, call.contentType)

        // §1.4 tuple: (bag key "id-register", empty query, exact body, raw push token).
        val fields = listOf(
            "id-register".toByteArray(),
            ByteArray(0),
            call.body,
            pushToken,
        )
        verifySignature(call, "x-push-nonce", "x-push-sig", PUSH, fields)
        verifySignature(call, "x-auth-nonce-0", "x-auth-sig-0", AUTH, fields)

        assertEquals(Base64.getEncoder().encodeToString(pushCert), call.headers.getValue("x-push-cert"))
        assertEquals(Base64.getEncoder().encodeToString(pushToken), call.headers.getValue("x-push-token"))
        assertEquals("user-1", call.headers.getValue("x-auth-user-id-0"))
        assertEquals(Base64.getEncoder().encodeToString(authCert), call.headers.getValue("x-auth-cert-0"))
        assertEquals("1660", call.headers.getValue("x-protocol-version"))
        assertEquals(
            "com.apple.invitation-registration [Test,1,1,Test]",
            call.headers.getValue("user-agent"),
        )
    }

    @Test
    fun phoneUserIdHeaderCarriesTheRecordedPFormVerbatim() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        registrar(http).register(body(user("P:+15557654321")))
        assertEquals("P:+15557654321", http.calls.single().headers.getValue("x-auth-user-id-0"))
    }

    private fun verifySignature(
        call: ScriptedIdsHttp.Call,
        nonceHeader: String,
        sigHeader: String,
        key: KeyPair,
        fields: List<ByteArray>,
    ) {
        val nonce = Base64.getDecoder().decode(call.headers.getValue(nonceHeader))
        assertEquals(17, nonce.size)
        assertEquals(0x01, nonce[0].toInt())
        val signature = Base64.getDecoder().decode(call.headers.getValue(sigHeader))
        assertContentEquals(byteArrayOf(0x01, 0x01), signature.copyOfRange(0, 2))
        val verifier = Signature.getInstance("SHA1withRSA")
        verifier.initVerify(key.public)
        verifier.update(IdsSigning.signingBytes(nonce, fields))
        assertTrue(verifier.verify(signature.copyOfRange(2, signature.size)), "$sigHeader does not verify")
    }

    @Test
    fun registerBodyCarriesExactlyTheRecordedTopLevelKeys() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        registrar(http).register(body())

        val decoded = Plist.parse(http.calls.single().body) as Map<*, *>
        assertEquals(
            setOf(
                "device-name", "hardware-version", "language", "os-version", "software-version",
                "private-device-data", "services", "validation-data",
            ),
            decoded.keys,
        )
        assertEquals("LP3", decoded["device-name"])
        assertEquals("h1", decoded["hardware-version"])
        assertEquals("en", decoded["language"])
        assertEquals("14.6.1", decoded["os-version"])
        assertEquals("1.0", decoded["software-version"])
        assertContentEquals(byteArrayOf(1, 2, 3), decoded["validation-data"] as ByteArray)
    }

    @Test
    fun serviceEntryCarriesTheRecordedKeys() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        registrar(http).register(body())

        val decoded = Plist.parse(http.calls.single().body) as Map<*, *>
        val service = (decoded["services"] as List<*>).single() as Map<*, *>
        assertEquals(setOf("capabilities", "service", "sub-services", "users"), service.keys)
        assertEquals("com.apple.madrid", service["service"])
        assertEquals(RegisterService.SUB_SERVICES, service["sub-services"])
        val capability = (service["capabilities"] as List<*>).single() as Map<*, *>
        // C3 disagreement: 17 (first-recorded) is the default; record keys are settled (§1.4).
        assertEquals(mapOf("flags" to 17L, "name" to "Messenger", "version" to 1L), capability)
        val user = (service["users"] as List<*>).single() as Map<*, *>
        assertEquals("user-1", user["user-id"])
        assertEquals(listOf(mapOf("uri" to "tel:+15557654321")), user["uris"])
        assertEquals(mapOf("client-data-version" to 2L), user["client-data"])
        assertTrue(!user.containsKey("tag"), "null tag must be omitted")
    }

    @Test
    fun sevenTopicSubServiceListIsAvailableForTheC3Disagreement() {
        assertEquals(RegisterService.SUB_SERVICES.size + 3, RegisterService.SUB_SERVICES_SEVEN.size)
        assertTrue(RegisterService.SUB_SERVICES_SEVEN.containsAll(RegisterService.SUB_SERVICES))
    }

    @Test
    fun privateDeviceDataCarriesTheRecordedKeys() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        registrar(http).register(body())

        val decoded = Plist.parse(http.calls.single().body) as Map<*, *>
        assertEquals(
            mapOf(
                "ap" to "0",
                "d" to "800000000",
                "dt" to 1L,
                "gt" to "0",
                "h" to "1",
                "m" to "0",
                "p" to "0",
                "pb" to "24G84",
                "pn" to "Mac15,12",
                "pv" to "14.6.1",
                "s" to "0",
                "t" to "0",
                "u" to "ABCD-EF",
                "v" to "1",
            ),
            decoded["private-device-data"],
        )
    }

    @Test
    fun relayProfileFlipsMAndS() {
        val dict = PrivateDeviceData("b", "p", "v", "u", 1L, relayProfile = true).toDict()
        assertEquals("1", dict["m"])
        assertEquals("1", dict["s"])
    }

    @Test
    fun responseParsesTheRecordedResponseKeys() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        val response = registrar(http).register(body())

        assertEquals(0, response.status)
        assertEquals("ok", response.message)
        assertEquals(600L, response.retryInterval)
        val service = response.services.single()
        assertEquals("com.apple.madrid", service.service)
        assertEquals(0, service.status)
        val user = service.users.single()
        assertEquals("user-1", user.userId)
        assertEquals(0, user.status)
        assertEquals(86400L, user.nextHbi)
        assertContentEquals(authCert, user.cert)
        assertEquals(listOf(IdsRegisterUriResult("tel:+15557654321", 0)), user.uris)
        assertEquals("Test title", user.alert?.title)
        assertEquals("Test body", user.alert?.body)
        assertEquals("OK", user.alert?.button)
        assertEquals("https://example/alert", user.alert?.action?.url)
        assertEquals("button", user.alert?.action?.button)
        assertEquals("url", user.alert?.action?.type)
    }

    @Test
    fun responseUsersRideInsideServices() = runBlocking {
        // §1.4: the response nests users per service; a top-level users array is not recorded.
        val response = XmlPlist.encode(
            mapOf(
                "status" to 0L,
                "services" to listOf(
                    mapOf("service" to "com.apple.madrid", "status" to 0L, "users" to listOf<Any?>(mapOf("status" to 0L))),
                ),
            ),
        )
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))
        val parsed = registrar(http).register(body())

        assertEquals(1, parsed.services.single().users.size)
        assertEquals(null, parsed.services.single().users[0].nextHbi)
        assertEquals(null, parsed.retryInterval)
    }

    @Test
    fun refreshCredentialsMarkerMarksTheAuthPairWhenConfigured() = runBlocking {
        val response = XmlPlist.encode(
            mapOf(
                "status" to 0L,
                "services" to listOf(
                    mapOf(
                        "service" to "com.apple.madrid",
                        "status" to 0L,
                        "users" to listOf(mapOf("status" to "refresh credentials", "user-id" to "user-1")),
                    ),
                ),
            ),
        )
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))

        val parsed = registrar(http, refreshMarker = "refresh credentials").register(body())

        assertEquals(true, parsed.services.single().users.single().refreshCredentials)
        assertEquals(null, parsed.services.single().users.single().status)
    }

    @Test
    fun unconfiguredOrUnknownStringStatusesFailLoudly() {
        // §6.1's "refresh credentials" marker is capture-bound — never guessed.
        val response = XmlPlist.encode(
            mapOf(
                "status" to 0L,
                "services" to listOf(
                    mapOf("service" to "s", "status" to 0L, "users" to listOf(mapOf("status" to "refresh credentials"))),
                ),
            ),
        )
        val unconfigured = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))
        assertFailsWith<IdsActivationException> {
            runBlocking { registrar(unconfigured).register(body()) }
        }

        val mismatched = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))
        assertFailsWith<IdsActivationException> {
            runBlocking { registrar(mismatched, refreshMarker = "other marker").register(body()) }
        }
    }

    @Test
    fun missingStatusThrows() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("message" to "ok")))))
        assertFailsWith<IdsActivationException> {
            runBlocking { registrar(http).register(body()) }
        }
    }

    @Test
    fun non200Throws() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(429, emptyMap(), ByteArray(0))))
        assertFailsWith<IdsActivationException> {
            runBlocking { registrar(http).register(body()) }
        }
    }

    @Test
    fun unparseableResponseThrows() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), "not a plist".toByteArray())))
        assertFailsWith<IdsActivationException> {
            runBlocking { registrar(http).register(body()) }
        }
    }

    @Test
    fun missingRegisterBagKeyIsTheBagError() {
        val http = ScriptedIdsHttp(emptyList())
        val client = IdsRegistrar(http, Bag(emptyMap()), config())
        assertFailsWith<BagKeyMissingException> {
            runBlocking { client.register(body()) }
        }
        assertEquals(0, http.calls.size)
    }

    @Test
    fun authenticateSendsTheRecordedBodyKeysAndHeaderSet() = runBlocking {
        val response = XmlPlist.encode(mapOf("status" to 0L, "cert" to authCert))
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))
        val authenticator = IdsAuthenticator(http, Bag(mapOf(IdsAuthenticator.BAG_KEY_DS_ID to authUrl)), "1660", "ua")

        val parsed = authenticator.authenticate(
            IdsAuthenticator.BAG_KEY_DS_ID,
            realmUserId = "user@example.com",
            csrDer = AUTH_CSR.der,
            authenticationData = AuthenticationData.AuthToken("auth-token-1"),
        )

        val call = http.calls.single()
        assertEquals(authUrl, call.url)
        // §1.2: ONLY user-agent and x-protocol-version, plus content-encoding: gzip. No §1.4 signature headers.
        assertEquals(setOf("user-agent", "x-protocol-version", "content-encoding"), call.headers.keys)
        assertEquals("gzip", call.headers.getValue("content-encoding"))
        assertEquals("1660", call.headers.getValue("x-protocol-version"))
        assertEquals("ua", call.headers.getValue("user-agent"))

        // The body is gzipped (content-encoding) XML plist with exactly the recorded keys.
        assertEquals(0x1f, call.body[0].toInt() and 0xff)
        assertEquals(0x8b, call.body[1].toInt() and 0xff)
        val decoded = Plist.parse(gunzipIfNeeded(call.body)) as Map<*, *>
        assertEquals(setOf("authentication-data", "csr", "realm-user-id"), decoded.keys)
        assertEquals(mapOf("auth-token" to "auth-token-1"), decoded["authentication-data"])
        assertEquals("user@example.com", decoded["realm-user-id"])
        assertContentEquals(AUTH_CSR.der, decoded["csr"] as ByteArray)

        // §1.2: flat status + cert response, no per-user nesting.
        assertEquals(0, parsed.status)
        assertContentEquals(authCert, parsed.cert)
    }

    @Test
    fun phoneFlowUsesThePhoneNumberBagKeyAndPushAuthenticationData() = runBlocking {
        val response = XmlPlist.encode(mapOf("status" to 0L, "cert" to authCert))
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), response)))
        val authenticator = IdsAuthenticator(
            http,
            Bag(mapOf(IdsAuthenticator.BAG_KEY_PHONE_NUMBER to phoneAuthUrl)),
            "1660",
            "ua",
        )

        authenticator.authenticate(
            IdsAuthenticator.BAG_KEY_PHONE_NUMBER,
            realmUserId = "P:+15557654321",
            csrDer = AUTH_CSR.der,
            authenticationData = AuthenticationData.Push(
                pushToken = "push-token-1",
                sigs = listOf("sig-1"),
            ),
        )

        val call = http.calls.single()
        assertEquals(phoneAuthUrl, call.url)
        val decoded = Plist.parse(gunzipIfNeeded(call.body)) as Map<*, *>
        assertEquals("P:+15557654321", decoded["realm-user-id"])
        assertEquals(
            mapOf("push-token" to "push-token-1", "sigs" to listOf("sig-1")),
            decoded["authentication-data"],
        )
    }

    @Test
    fun authenticateCnIsTheHexSha1RealmUserIdWithTheDefaultCase() {
        // The full §1.2 path: 2048-bit RSA key, CN = hex SHA-1 of the realm user id (§1.2, C57 case parameter).
        val cn = IdsCsrBuilder.realmUserIdCn("P:+15557654321")
        assertEquals("99F8BAD26E4592AEC848DB65117BD551A9955163", cn)
        val csr = IdsCsrBuilder.create(AUTH, cn)
        assertEquals(listOf(cn), csrSubjectValues(csr.der))
    }

    @Test
    fun authenticateRefusesBagKeysThatAreNotRecordedAuthenticateEndpoints() {
        val http = ScriptedIdsHttp(emptyList())
        val authenticator = IdsAuthenticator(http, Bag(mapOf("id-query" to "https://other")), "1660", "ua")
        assertFailsWith<IllegalArgumentException> {
            runBlocking {
                authenticator.authenticate("id-query", "user", AUTH_CSR.der, AuthenticationData.AuthToken("t"))
            }
        }
        assertEquals(0, http.calls.size)
    }

    @Test
    fun authenticateMissingBagKeyIsTheBagError() {
        val http = ScriptedIdsHttp(emptyList())
        val authenticator = IdsAuthenticator(http, Bag(emptyMap()), "1660", "ua")
        assertFailsWith<BagKeyMissingException> {
            runBlocking {
                authenticator.authenticate(
                    IdsAuthenticator.BAG_KEY_DS_ID,
                    "user",
                    AUTH_CSR.der,
                    AuthenticationData.AuthToken("t"),
                )
            }
        }
    }

    private fun okResponse(): ByteArray = XmlPlist.encode(
        mapOf(
            "status" to 0L,
            "message" to "ok",
            "retry-interval" to 600L,
            "services" to listOf(
                mapOf(
                    "service" to "com.apple.madrid",
                    "status" to 0L,
                    "users" to listOf(
                        mapOf(
                            "user-id" to "user-1",
                            "status" to 0L,
                            "next-hbi" to 86400L,
                            "cert" to authCert,
                            "uris" to listOf(mapOf("uri" to "tel:+15557654321", "status" to 0L)),
                            "alert" to mapOf(
                                "title" to "Test title",
                                "body" to "Test body",
                                "button" to "OK",
                                "action" to mapOf("button" to "button", "type" to "url", "url" to "https://example/alert"),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )

    private companion object {
        // 1024-bit test keys, per the IdsLookupTest precedent — never hardcoded key material.
        val PUSH: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val AUTH: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }.generateKeyPair()
        val AUTH_CSR: IdsCsr = IdsCsrBuilder.create(AUTH, "df88e39ca8b5cfdfd8da5d9b927d0535374f6fd7")
    }
}
