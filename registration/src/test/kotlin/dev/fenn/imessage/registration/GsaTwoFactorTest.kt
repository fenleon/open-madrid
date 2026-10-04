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
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The §1.5 2FA paths against scripted transports: the `secondaryAuth` SMS sequence (extras →
 * verify/phone → verify/phone/securitycode), the `trustedDeviceSecondaryAuth` sequence
 * (trusteddevice trigger → `validate` with the `security-code` header), the
 * `X-Apple-Identity-Token` header, and the response-header token parsing.
 */
class GsaTwoFactorTest {

    private val identityToken = gsaIdentityToken("adsid-1", "idms-token-1")

    private fun client(http: IdsHttp) = GsaTwoFactorClient(
        http = http,
        browserHeaders = { browserHeaders() },
        authBase = "https://gsa.example/auth",
        validateUrl = "https://gsa.example/GsService2/validate",
        trustedDeviceUrl = "https://gsa.example/auth/verify/trusteddevice",
    )

    /** The recorded §1.5 set; [device] feeds the recorded non-akd client-info template. */
    private fun browserHeaders(
        device: GsaHeaderConfig? = null,
        userAgent: String = GsaTwoFactorHeaders.BROWSER_USER_AGENT,
    ) = GsaTwoFactorHeaders.of(
        GsaCpd(
            anisette = mapOf(
                "X-Apple-I-MD" to "otp",
                "X-Apple-I-MD-RINFO" to "17106176",
                "X-Apple-I-MD-M" to "machine-id",
                "X-Mme-Device-Id" to "device-id",
            ),
            keychainIdentifier = ByteArray(16) { it.toByte() },
        ),
        device = device,
        userAgent = userAgent,
    )

    private fun petHeader(value: String) = mapOf(
        "X-Apple-PE-Token" to Base64.getEncoder().encodeToString(value.toByteArray()),
    )

    @Test
    fun `authentication extras parse the recorded JSON fields`() = runBlocking {
        val json = """
            {"trustedPhoneNumbers":[{"numberWithDialCode":"+1 555 000 1111","lastTwoDigits":"11",
            "pushMode":false,"id":7}],"other":"field"}
        """.trimIndent()
        val extras = client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), json.toByteArray()))))
            .trustedPhoneNumbers(identityToken)

        val phone = extras.trustedPhoneNumbers.single()
        assertEquals("+1 555 000 1111", phone.numberWithDialCode)
        assertEquals("11", phone.lastTwoDigits)
        assertEquals(false, phone.pushMode)
        assertEquals(7L, phone.id)
    }

    @Test
    fun `http 201 means the SMS was already sent and still parses`() = runBlocking {
        val client = client(ScriptedIdsHttp(listOf(IdsHttpResponse(201, emptyMap(), "{}".toByteArray()))))
        assertEquals(emptyList(), client.trustedPhoneNumbers(identityToken).trustedPhoneNumbers)
    }

    @Test
    fun `other statuses fail loudly`() = runBlocking {
        val client = client(ScriptedIdsHttp(listOf(IdsHttpResponse(401, emptyMap(), ByteArray(0)))))
        assertFailsWith<GsaLoginException> { client.trustedPhoneNumbers(identityToken) }
        Unit
    }

    @Test
    fun `sms request is a PUT with the recorded JSON body`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), ByteArray(0))))
        client(http).requestSmsCode(identityToken, "7")

        val call = http.calls.single()
        assertEquals("PUT", call.method)
        assertEquals("https://gsa.example/auth/verify/phone", call.url)
        assertEquals("application/json", call.headers["Content-Type"])
        assertEquals("application/json", call.contentType)
        val body = Json.parseToJsonElement(call.body.decodeToString()).jsonObject
        assertEquals("7", body["phoneNumber"]!!.jsonObject["id"]!!.jsonPrimitive.content)
        assertEquals("sms", body["mode"]!!.jsonPrimitive.content)
        assertEquals(identityToken, call.headers["X-Apple-Identity-Token"])
        assertEquals("same-origin", call.headers["Sec-Fetch-Site"])
    }

    @Test
    fun `the recorded 2FA browser header set carries the literal values`() {
        val device = GsaHeaderConfig(
            hardwareModel = "iMac13,1",
            osName = "macOS",
            osVersion = "13.6.4",
            osBuild = "22G513",
        )
        val headers = browserHeaders(device = device).toHeaders()
        val expected = mapOf(
            "X-Apple-I-MD" to "otp",
            "X-Apple-I-MD-RINFO" to "17106176",
            "X-Apple-I-MD-M" to "machine-id",
            "X-Mme-Device-Id" to "device-id",
            "X-Apple-I-MD-LU" to
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest(ByteArray(16) { it.toByte() })
                    .joinToString("") { "%02x".format(it) },
            "X-Apple-Client-App-Name" to "Messages",
            "X-Apple-I-Client-Bundle-Id" to "com.apple.MobileSMS",
            // Spec §1.5 rev-15 closure: the device-bracket form with the fixed
            // `com.apple.akd/1.0 (com.apple.akd/1.0)` inner component.
            "X-MMe-Client-Info" to "<iMac13,1> <macOS;13.6.4;22G513> <com.apple.akd/1.0 (com.apple.akd/1.0)>",
            "X-Apple-I-CDP-Circle-Status" to "false",
            "X-Apple-I-ICSCREC" to "true",
            // Spec §1.5 rev-15 closure: the browser UA literal — NO Safari/Version token.
            "User-Agent" to
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
            "Sec-Fetch-Site" to "same-origin",
            "X-Apple-Requested-Partition" to "0",
            "X-Apple-I-DeviceUserMode" to "0",
            "X-Apple-I-Locale" to "en_US",
            "X-Apple-Security-Upgrade-Context" to "com.apple.authkit.generic",
            "Accept-Language" to "en-US,en;q=0.9",
            "X-Apple-I-PRK-Gen" to "true",
            "Sec-Fetch-Mode" to "cors",
            "X-Apple-I-TimeZone" to "UTC",
            "X-Apple-I-OT-Status" to "false",
            "X-Apple-I-TimeZone-Offset" to "0",
            "X-MMe-Country" to "US",
            "X-Apple-I-CDP-Status" to "false",
            "X-Apple-I-Device-Configuration-Mode" to "0",
            "Sec-Fetch-Dest" to "empty",
            "X-Apple-AK-Context-Type" to "imessage",
            "X-Apple-I-CFU-State" to GsaTwoFactorHeaders.CFU_STATE,
        )
        assertEquals(expected, headers)
    }

    @Test
    fun `without device slots the non-akd client-info is omitted`() {
        val headers = browserHeaders().toHeaders()
        assertEquals(false, headers.containsKey("X-MMe-Client-Info"))
        assertEquals(GsaTwoFactorHeaders.BROWSER_USER_AGENT, headers["User-Agent"])
    }

    @Test
    fun `cfu state is base64 of the full 182-byte plist wrapper`() {
        val decoded = Base64.getDecoder().decode(GsaTwoFactorHeaders.CFU_STATE)
        // Spec-pinned: the decoded shape (prolog + Apple DOCTYPE + plist open + empty array +
        // plist close + trailing newline) and its exact 182-byte decoded length (§1.5).
        assertEquals(182, decoded.size)
        assertEquals(GsaTwoFactorHeaders.CFU_STATE_PLIST, String(decoded, Charsets.US_ASCII))
        val text = String(decoded, Charsets.UTF_8)
        assertTrue(text.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"))
        assertTrue(text.contains("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\""))
        assertTrue(text.contains("<plist version=\"1.0\">\n<array/>\n</plist>\n"))
        // NOT the previously-assumed bare `<array/>`.
        assertTrue(decoded.size != "<array/>".length)
        // And it parses as a plist whose value is an empty array.
        val parsed = XmlPlist.decode(decoded)
        assertTrue(parsed is List<*> && parsed.isEmpty())
    }

    @Test
    fun `sms verification posts the security code and parses the token headers`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(
                    200,
                    petHeader("com.apple.gs.idms.pet:pet-token:1800000000000") +
                        mapOf(
                            "X-Apple-GS-Token" to listOf(
                                Base64.getEncoder().encodeToString("svc.a:tok-a".toByteArray()),
                                Base64.getEncoder().encodeToString("svc.b:tok-b".toByteArray()),
                            ).joinToString(","),
                            "X-Apple-HB-Token" to Base64.getEncoder().encodeToString("hb:hv".toByteArray()),
                        ),
                    ByteArray(0),
                ),
            ),
        )
        val tokens = client(http).submitSmsCode(identityToken, "7", "123456", nowEpochMs = 5_000L)

        val call = http.calls.single()
        assertEquals("POST", call.method)
        assertEquals("https://gsa.example/auth/verify/phone/securitycode", call.url)
        val body = Json.parseToJsonElement(call.body.decodeToString()).jsonObject
        assertEquals("123456", body["securityCode"]!!.jsonObject["code"]!!.jsonPrimitive.content)
        assertEquals(identityToken, call.headers["X-Apple-Identity-Token"])

        assertEquals("pet-token", tokens.pet?.token)
        assertEquals("tok-a", tokens.gsTokens.getValue("svc.a").token)
        assertEquals("tok-b", tokens.gsTokens.getValue("svc.b").token)
        assertEquals("hv", tokens.hbTokens.single().token)
    }

    @Test
    fun `trusted device flow triggers then validates with the security-code header`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(200, emptyMap(), ByteArray(0)),
                IdsHttpResponse(200, petHeader("com.apple.gs.idms.pet:pet-2"), ByteArray(0)),
            ),
        )
        val twoFactor = client(http)
        twoFactor.triggerTrustedDevice(identityToken)
        val tokens = twoFactor.submitTrustedDeviceCode(identityToken, "987654", nowEpochMs = 5_000L)

        assertEquals("GET", http.calls[0].method)
        assertEquals("https://gsa.example/auth/verify/trusteddevice", http.calls[0].url)
        assertEquals("GET", http.calls[1].method)
        assertEquals("https://gsa.example/GsService2/validate", http.calls[1].url)
        assertEquals("987654", http.calls[1].headers["security-code"])
        assertEquals(identityToken, http.calls[1].headers["X-Apple-Identity-Token"])
        assertEquals("pet-2", tokens.pet?.token)
        assertEquals(5_000L + 300_000, tokens.pet?.expiresAtEpochMs) // 300 s default, §1.5
    }

    @Test
    fun `failed verification fails loudly`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(403, emptyMap(), ByteArray(0))))
        val client = client(http)
        assertFailsWith<GsaLoginException> {
            client.submitSmsCode(identityToken, "7", "000000", nowEpochMs = 5_000L)
        }
        Unit
    }

    @Test
    fun `identity token value is base64 of adsid colon idms token`() {
        val decoded = String(Base64.getDecoder().decode(identityToken))
        assertEquals("adsid-1:idms-token-1", decoded)
        assertTrue(!decoded.startsWith(":") && !decoded.endsWith(":"))
    }
}
