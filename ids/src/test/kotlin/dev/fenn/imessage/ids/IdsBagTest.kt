package dev.fenn.imessage.ids

import dev.fenn.imessage.codec.NativePlist
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.coroutines.runBlocking

/**
 * Scripted [IdsHttp] test double: hands back [responses] in order and records every call.
 * One response per expected call — an unscripted extra call throws.
 */
class ScriptedIdsHttp(private val responses: List<IdsHttpResponse>) : IdsHttp {

    class Call(
        val method: String,
        val url: String,
        val headers: Map<String, String>,
        val body: ByteArray,
        val contentType: String,
    )

    val calls = mutableListOf<Call>()
    private var next = 0

    override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse {
        calls.add(Call("GET", url, headers, ByteArray(0), ""))
        return responses[next++]
    }

    override suspend fun put(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        calls.add(Call("PUT", url, headers, body, contentType))
        return responses[next++]
    }

    override suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        calls.add(Call("POST", url, headers, body, contentType))
        return responses[next++]
    }
}

class IdsBagTest {

    private val idQueryUrl = "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query"

    // Port note: the originating repo's fixtures serialized the bag responses as XML plists
    // (the archived bags are XML per spec §1.2 [CAP-BAGCT]); this repo's plist codec is
    // binary-only, so the same shapes ride binary plists — outer dict with `signature`,
    // `certs` and `bag`, the embedded `bag` data itself a plist (the interesting combination).
    private fun idsBagResponse(): ByteArray {
        val inner = NativePlist.encode(
            mapOf("id-query" to idQueryUrl, "id-register" to "https://identity.ess.apple.com/register"),
        )
        return NativePlist.encode(
            mapOf(
                "signature" to ByteArray(1),
                "certs" to listOf(ByteArray(1)),
                "bag" to inner,
            ),
        )
    }

    private fun apnsBagResponse(): ByteArray = NativePlist.encode(
        mapOf(
            "APNSCourierHostname" to "courier.push.apple.com",
            "APNSCourierHostcount" to 50L,
        ),
    )

    @Test
    fun idsBagUnwrapsTheEmbeddedFlatDictionary() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), idsBagResponse())))
        val bag = IdsBagFetcher(http).idsBag()

        assertEquals(idQueryUrl, bag.url("id-query"))
        assertEquals("https://identity.ess.apple.com/register", bag.url("id-register"))
        assertEquals(IdsBagFetcher.IDS_BAG_URL, http.calls.single().url)
    }

    @Test
    fun missingKeyIsItsOwnError() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), idsBagResponse())))
        val bag = IdsBagFetcher(http).idsBag()

        val missing = assertFailsWith<BagKeyMissingException> { bag.url("id-authenticate-ds-id") }
        assertEquals("id-authenticate-ds-id", missing.key)
        assertEquals("bag has no key 'id-authenticate-ds-id'", missing.message)
    }

    @Test
    fun wrongValueTypeIsAParseError() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), idsBagResponse())))
        val bag = IdsBagFetcher(http).idsBag()

        assertFailsWith<IdsBagException> { bag.long("id-query") } // a URL where an integer is expected
        assertFailsWith<IdsBagException> { Bag(mapOf("APNSCourierHostcount" to 50L)).string("APNSCourierHostcount") }
        assertEquals(50L, Bag(mapOf("APNSCourierHostcount" to 50L)).long("APNSCourierHostcount"))
    }

    @Test
    fun bagIsFetchedOncePerProcess() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), idsBagResponse())))
        val fetcher = IdsBagFetcher(http)

        fetcher.idsBag()
        fetcher.idsBag()

        assertEquals(1, http.calls.size)
    }

    @Test
    fun non200IsAFetchFailure() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(503, emptyMap(), ByteArray(0))))

        runBlocking { assertFailsWith<IdsBagException> { IdsBagFetcher(http).idsBag() } }
    }

    @Test
    fun bodyThatIsNotAPlistIsAFetchFailure() {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), "hi".toByteArray())))

        runBlocking { assertFailsWith<IdsBagException> { IdsBagFetcher(http).idsBag() } }
    }

    @Test
    fun apnsBagIsFetchedOverPlainHttpAndYieldsTheCourierEndpoint() = runBlocking {
        val http = ScriptedIdsHttp(listOf(IdsHttpResponse(200, emptyMap(), apnsBagResponse())))
        val fetcher = IdsBagFetcher(http)

        val endpoint = fetcher.courierEndpoint()

        assertEquals("http://init-p01st.push.apple.com/bag", http.calls.single().url)
        assertEquals("courier.push.apple.com", endpoint.hostname)
        assertEquals(50, endpoint.hostCount)
        assertEquals(dev.fenn.imessage.courier.CourierClient.Config(endpoint.hostname, endpoint.hostCount).hostname, endpoint.hostname)
    }

    @Test
    fun apnsBagMissingHostnameIsALoudKeyError() {
        val http = ScriptedIdsHttp(
            listOf(IdsHttpResponse(200, emptyMap(), NativePlist.encode(mapOf("other" to "x")))),
        )

        runBlocking { assertFailsWith<BagKeyMissingException> { IdsBagFetcher(http).courierEndpoint() } }
    }
}
