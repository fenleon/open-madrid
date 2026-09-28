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
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/**
 * The §1.5 delegate login: POST to `setup.icloud.com/setup/signin/v2/login` with the recorded
 * body (`delegates`, `protocolVersion`, `userInfo`) and header set (Basic `username:PET`,
 * `X-Mme-Nas-Qualify`, `X-Apple-ADSID`, `X-Mme-Client-Info`, `User-Agent`, anisette), and the
 * response parse yielding the IDS delegate's `auth-token`/`profile-id` — kebab-case
 * serviceData, loud on every deviation.
 */
class GsaDelegateLoginTest {

    private fun client(http: IdsHttp) =
        GsaDelegateLoginClient(http, endpoint = "https://setup.example.com/setup/signin/v2/login")

    private fun request() = IcloudSignInRequest(
        username = "user@example.com",
        pet = "pet-token",
        adsid = "adsid-1",
        validationData = byteArrayOf(1, 2, 3),
        clientId = "A1B2C3D4-E5F6-4789-ABCD-0123456789AB",
        timezone = "Europe/Berlin",
        clientInfo = "macOS;13.5;22G74",
        anisette = mapOf("X-Apple-I-MD" to "otp"),
    )

    private fun okResponse(): ByteArray = XmlPlist.encode(
        mapOf(
            "status" to 0L,
            "delegates" to linkedMapOf(
                "com.apple.private.ids" to linkedMapOf<String, Any?>(
                    "status" to 0L,
                    "statusMessage" to "",
                    "serviceData" to linkedMapOf<String, Any?>(
                        "auth-token" to "ids-auth-token",
                        "profile-id" to "profile-1",
                    ),
                ),
                "com.apple.mobileme" to linkedMapOf<String, Any?>(
                    "status" to 0L,
                    "serviceData" to linkedMapOf<String, Any?>("mmeAuthToken" to "mme-token"),
                ),
            ),
        ),
    )

    @Test
    fun `recorded sign-in values are the defaults`() {
        val request = IcloudSignInRequest(
            username = "user@example.com",
            pet = "pet-token",
            adsid = "adsid-1",
            validationData = byteArrayOf(1),
            clientId = "A1B2C3D4-E5F6-4789-ABCD-0123456789AB",
            anisette = emptyMap(),
        )
        assertEquals("America/New_York", request.timezone)
        assertEquals("com.apple.AOSKit/282 (com.apple.accountsd/113)", request.clientInfo)
        assertEquals(
            "com.apple.iCloudHelper/282 com.apple.iCloudHelper/282",
            GsaDelegateLoginClient.SIGNIN_USER_AGENT,
        )
    }

    @Test
    fun `posts the recorded body and headers`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse())))
        client(http).signIn(request())

        val call = http.calls.single()
        assertEquals("POST", call.method)
        assertEquals("https://setup.example.com/setup/signin/v2/login", call.url)
        assertEquals("application/x-apple-plist", call.contentType)
        assertEquals("Basic " + Base64.getEncoder().encodeToString("user@example.com:pet-token".toByteArray()),
            call.headers["Authorization"])
        assertEquals(Base64.getEncoder().encodeToString(byteArrayOf(1, 2, 3)), call.headers["X-Mme-Nas-Qualify"])
        assertEquals("adsid-1", call.headers["X-Apple-ADSID"])
        assertEquals("macOS;13.5;22G74", call.headers["X-Mme-Client-Info"])
        assertEquals(GsaDelegateLoginClient.SIGNIN_USER_AGENT, call.headers["User-Agent"])
        assertEquals("otp", call.headers["X-Apple-I-MD"])

        val body = XmlPlist.decode(call.body) as Map<*, *>
        assertEquals("1.0", body["protocolVersion"])
        val delegates = body["delegates"] as Map<*, *>
        assertEquals(mapOf("protocol-version" to "4"), delegates["com.apple.private.ids"])
        assertEquals(emptyMap<String, String>(), delegates["com.apple.mobileme"])
        val userInfo = body["userInfo"] as Map<*, *>
        assertEquals(
            mapOf(
                "clientId" to "A1B2C3D4-E5F6-4789-ABCD-0123456789AB",
                "language" to "en-US",
                "timezone" to "Europe/Berlin",
            ),
            userInfo,
        )
    }

    @Test
    fun `parses the ids delegate credentials`() = runBlocking {
        val response = client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), okResponse()))))
            .signIn(request())
        assertEquals(0, response.status)
        assertNull(response.localizedError)
        assertEquals(2, response.delegates.size)
        val credentials = response.idsDelegateCredentials()
        assertEquals("ids-auth-token", credentials.authToken)
        assertEquals("profile-1", credentials.profileId)
    }

    @Test
    fun `account-level failure surfaces loudly`() = runBlocking {
        val bad = XmlPlist.encode(
            linkedMapOf<String, Any?>(
                "status" to 2L,
                "localizedError" to "already-signed-in",
                "description" to "another sign-in is active",
            ),
        )
        val exception = assertFailsWith<GsaLoginException> {
            runBlocking {
                client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), bad)))).signIn(request())
                    .idsDelegateCredentials()
            }
        }
        assertTrue(exception.message!!.contains("already-signed-in"))
    }

    @Test
    fun `delegate-level failure surfaces loudly`() = runBlocking {
        val bad = XmlPlist.encode(
            mapOf(
                "status" to 0L,
                "delegates" to mapOf(
                    "com.apple.private.ids" to linkedMapOf<String, Any?>("status" to 500L, "statusMessage" to "no ids"),
                ),
            ),
        )
        val exception = assertFailsWith<GsaLoginException> {
            runBlocking {
                client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), bad)))).signIn(request())
                    .idsDelegateCredentials()
            }
        }
        assertTrue(exception.message!!.contains("no ids"))
    }

    @Test
    fun `missing ids delegate or serviceData keys fail loudly`() = runBlocking {
        val noIds = XmlPlist.encode(mapOf("status" to 0L, "delegates" to emptyMap<String, Any?>()))
        val noToken = XmlPlist.encode(
            mapOf(
                "status" to 0L,
                "delegates" to mapOf(
                    "com.apple.private.ids" to mapOf(
                        "status" to 0L,
                        "serviceData" to linkedMapOf<String, Any?>("profile-id" to "p"),
                    ),
                ),
            ),
        )
        val client = client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), noIds))))
        val missingDelegate = assertFailsWith<GsaLoginException> {
            runBlocking { client.signIn(request()).idsDelegateCredentials() }
        }
        assertTrue(missingDelegate.message!!.contains("com.apple.private.ids"))
        val client2 = client(ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), noToken))))
        val missingToken = assertFailsWith<GsaLoginException> {
            runBlocking { client2.signIn(request()).idsDelegateCredentials() }
        }
        assertTrue(missingToken.message!!.contains("auth-token"))
    }

    @Test
    fun `non-200 fails loudly`() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(401, emptyMap(), ByteArray(0))))
        val exception = assertFailsWith<GsaLoginException> { client(http).signIn(request()) }
        assertTrue(exception.message!!.contains("HTTP 401"))
    }
}
