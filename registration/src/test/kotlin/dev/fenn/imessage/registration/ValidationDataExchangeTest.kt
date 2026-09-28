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

/**
 * The §1.1 three-step exchange against a scripted transport.
 *
 * - **Spec-pinned**: the step-1 GET (bag URL → single `cert` data field), the step-2 POST
 *   (single-key `session-info-request` plist body, NO anisette/auth headers → `session-info`
 *   data), the bag-key names, and the blob hand-off forms (`validation-data` bytes /
 *   `X-Mme-Nas-Qualify` base64).
 * - **Reconstruction-shape**: that the step-3 context's output is a well-framed signed blob
 *   (the strategy hypothesis; the live server arbitrates — C5/C6 remaining).
 */
class ValidationDataExchangeTest {

    private val cert = byteArrayOf(1, 2, 3, 4)
    private val bagUrl = IdsBagFetcher.IDS_BAG_URL
    private val certUrl = "https://identity.example.com/validation-cert"
    private val initUrl = "https://identity.example.com/initialize-validation"

    private fun identifiers() = MacHardwareIdentifiers(
        serialNumber = "C02SERIAL",
        logicBoardSerial = "MLB-STRING",
        rom = byteArrayOf(9, 8, 7),
        productName = "Macmini9,1",
        macAddress = byteArrayOf(1, 2, 3, 4, 5, 6),
        platformUuid = "PLATFORM-UUID",
        rootDiskUuid = "ROOT-DISK-UUID",
        boardId = "Mac-AAAA",
        osBuildNumber = "22G513",
        serialEnc = byteArrayOf(10),
        platformUuidEnc = byteArrayOf(11),
        rootDiskUuidEnc = byteArrayOf(12),
        romEnc = byteArrayOf(13),
        mlbEnc = byteArrayOf(14),
    )

    private fun bagResponse(): ByteArray = XmlPlist.encode(
        mapOf(
            ValidationBagKeys.CERT to certUrl,
            ValidationBagKeys.INITIALIZE to initUrl,
        ),
    )

    private fun serverSessionInfo(): ByteArray {
        // A real P-256 point: the RAW_PUBLIC_POINT reconstruction parses it as the server key.
        val server = EcKeys.p256(java.security.SecureRandom())
        return EcCrypto.compress(server.public)
    }

    private fun exchange(http: IdsHttp) = ValidationDataExchange(
        http = http,
        bags = IdsBagFetcher(http),
        logEvent = {},
    )

    @Test
    fun `the three steps run in the recorded order and the blob feeds both sinks`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(200, emptyMap(), bagResponse()),
                IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("cert" to cert))),
                IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("session-info" to serverSessionInfo()))),
            ),
        )
        val result = exchange(http).generate(identifiers(), nowEpochMs = 1_770_000_000_000L)

        // Step order and URLs: bag first (endpoints never hardcoded), then the two bag keys.
        assertEquals(3, http.calls.size)
        assertEquals("GET", http.calls[0].method)
        assertEquals(bagUrl, http.calls[0].url)
        assertEquals("GET", http.calls[1].method)
        assertEquals(certUrl, http.calls[1].url)
        assertEquals("POST", http.calls[2].method)
        assertEquals(initUrl, http.calls[2].url)

        // Step 2 is body-only: NO anisette, NO authentication headers (spec §1.1).
        assertTrue(http.calls[2].headers.isEmpty())
        assertEquals(ValidationCertClient.CONTENT_TYPE, http.calls[2].contentType)
        val requestBody = XmlPlist.decode(http.calls[2].body) as Map<*, *>
        val requestKeys = requestBody.keys.toList()
        assertEquals(listOf("session-info-request"), requestKeys)
        val requestBlob = requestBody["session-info-request"] as ByteArray
        assertEquals(
            listOf(ValidationDataFields.KA_PUBLIC_KEY, ValidationDataFields.SIGNING_PUBLIC_KEY),
            ValidationDataFraming.parse(requestBlob).map { it.tag }.takeLast(2),
        )

        // The final blob is the step-3 output: framed fields + the SIGNATURE field (last).
        val fields = ValidationDataFraming.parse(result.blob)
        assertEquals(ValidationDataFields.SIGNATURE, fields.last().tag)
        assertEquals(1_770_000_000_000L, result.generatedAtEpochMs)

        // Sink 1 — the IDS register body's `validation-data` field takes the blob verbatim (§1.4).
        val registerBody = XmlPlist.encode(mapOf("validation-data" to result.blob))
        assertTrue((XmlPlist.decode(registerBody) as Map<*, *>)["validation-data"] is ByteArray)

        // Sink 2 — the §1.5 X-Mme-Nas-Qualify header is the blob base64.
        assertEquals(result.blob.toList(), Base64.getDecoder().decode(result.nasQualify()).toList())
    }

    @Test
    fun `a step-1 response without a cert data field fails loudly`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(200, emptyMap(), bagResponse()),
                IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("wrong" to "shape"))),
            ),
        )
        assertFailsWith<ValidationDataException> {
            exchange(http).generate(identifiers(), nowEpochMs = 0)
        }
        Unit
    }

    @Test
    fun `a step-2 failure status fails loudly`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(
                IdsHttpResponse(200, emptyMap(), bagResponse()),
                IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("cert" to cert))),
                IdsHttpResponse(503, emptyMap(), ByteArray(0)),
            ),
        )
        assertFailsWith<ValidationDataException> {
            exchange(http).generate(identifiers(), nowEpochMs = 0)
        }
        Unit
    }

    @Test
    fun `a missing validation bag key fails loudly`() = runBlocking {
        val http = ScriptedIdsHttp(
            listOf(IdsHttpResponse(200, emptyMap(), XmlPlist.encode(mapOf("unrelated" to "key")))),
        )
        assertFailsWith<BagKeyMissingException> {
            exchange(http).generate(identifiers(), nowEpochMs = 0)
        }
        Unit
    }
}
