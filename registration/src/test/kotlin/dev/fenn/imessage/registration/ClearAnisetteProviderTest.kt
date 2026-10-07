package dev.fenn.imessage.registration

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.XmlPlist
import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsHttp
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Tests for the wire-level ClearADI provider (ClearAdiFraming + ClearAnisetteProvider).
 * The framing facts come from new.asm/finish.asm plus live-oracle probes of
 * librust_lib_bluebubbles (see WORKLOG session 19e); everything the probes could not pin is
 * TODO(live-capture) in the code and asserted only at the shape level here.
 */
class ClearAnisetteProviderTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte() }

    // ---- Spim parse ----------------------------------------------------------

    private fun spimBytes(field1: Int = 0, payload: ByteArray = ByteArray(240), tail: ByteArray = ByteArray(0)): ByteArray = buildSpim(field1, payload, tail)

    @Test
    fun spimParseExtractsFields() {
        val payload = ByteArray(240) { it.toByte() }
        val spim = Spim.parse(spimBytes(field1 = 0x01020304, payload = payload, tail = ByteArray(23)))
        assertEquals(0x01020304, spim.field1)
        assertEquals(240, spim.payloadLength)
        assertContentEquals(payload, spim.payload)
    }

    @Test
    fun spimParseRejectsShortPayloadAndBadLeftover() {
        // payload ≤ 59 B rejected (17efb33)
        assertFailsWith<SpimFormatException> { Spim.parse(spimBytes(payload = ByteArray(59))) }
        // > 23 trailing bytes rejected (live-pinned error 0x41)
        assertFailsWith<SpimFormatException> { Spim.parse(spimBytes(tail = ByteArray(24))) }
        // truncated header
        assertFailsWith<SpimFormatException> { Spim.parse(ByteArray(3)) }
        // payload length beyond the buffer
        val b = spimBytes()
        b[4] = 0x00; b[5] = 0x00; b[6] = 0x01; b[7] = 0x00
        assertFailsWith<SpimFormatException> { Spim.parse(b) }
    }

    // ---- Cpim build ----------------------------------------------------------

    /** Deterministic RNG: draws are 0x10, 0x20, 0x30-filled blocks (draw1, draw2, draw3). */
    private class FixedRng : ClearAdiRng {
        var n = 0
        override fun draw(n: Int): ByteArray {
            val fill = when (++this.n) { 1 -> 0x10; 2 -> 0x20; else -> 0x30 }.toByte()
            return ByteArray(n) { fill }
        }
    }

    private val seal = CpimTailSeal { _, _, sig, digest ->
        // the two 256-bit fields: shape-only seal so the test is deterministic
        sig.copyOf(32) to digest
    }

    @Test
    fun cpimBuildMatchesAsmLayout() {
        val extra = ByteArray(10) { 0xAB.toByte() }
        val session = ClearAdiProvision.initSession(ByteArray(240))
        val cpim = Cpim.build(FixedRng(), extra, -2L, session, ByteArray(240), seal)
        // 4+32+4+32+60+8+4+32+32
        assertEquals(208, cpim.size)
        assertEquals(32, readBeU32(cpim, 0))
        // vec1 = encsec(draw2) — encsec is deterministic, so byte-exact here
        assertContentEquals(ClearAdiProvision.encsec(ByteArray(32) { 0x20.toByte() }), cpim.copyOfRange(4, 36))
        assertEquals(32, readBeU32(cpim, 36))
        assertContentEquals(ByteArray(32) { 0x10.toByte() }, cpim.copyOfRange(40, 72)) // draw1 raw
        // blob = extra ‖ draw3 padding
        assertContentEquals(extra, cpim.copyOfRange(72, 82))
        assertContentEquals(ByteArray(50) { 0x30.toByte() }, cpim.copyOfRange(82, 132))
        // arg9 = −2 as u64 BE (omnisette "GSA")
        assertEquals(-2L, readBeU64(cpim, 132))
        assertContentEquals(hex("FFFFFFFFFFFFFFFE"), cpim.copyOfRange(132, 140))
        // item 7 = BE u32 of the LE dword at draw3[8..12] — draw3 is 0x30-filled ⇒ 0x30303030
        assertEquals(0x30303030, readBeU32(cpim, 140))
        // tail fields present, 32 B each (items 8–9 = 64 B after the 144 B prefix)
        assertEquals(64, cpim.size - 144)
    }

    @Test
    fun cpimBuildRejectsOversizeExtra() {
        assertFailsWith<IllegalArgumentException> {
            Cpim.build(FixedRng(), ByteArray(61), -2L, ByteArray(0x28F0), ByteArray(240), seal)
        }
    }

    // ---- Ptm parse / tk check ------------------------------------------------

    @Test
    fun ptmParseTakesField1AndPayload() {
        val ptm = Ptm.parse(hex("00000001") + ByteArray(32))
        assertEquals(1, ptm.field1)
        assertEquals(32, ptm.payload.size)
        // lenient Vec: field1 clipped to what the buffer holds (live-pinned)
        assertEquals(4, Ptm.parse(hex("FFFFFFFF") + ByteArray(4)).payload.size)
    }

    @Test
    fun finishRejectsTkNot16Bytes() = kotlinx.coroutines.runBlocking {
        val http = ScriptedIdsHttp(tkSize = 15)
        val provider = provider(http = http)
        val ex = assertFailsWith<ClearAdiProvisioningException> { provider.provision() }
        assertTrue(ex.message!!.contains("tk not exactly 16 bytes"))
    }

    // ---- ProvisionedData raw layout ------------------------------------------

    @Test
    fun provisionedDataExposesRawLayout() {
        val raw = ByteArray(0x78) { (it + 1).toByte() }
        val data = ProvisionedData(raw)
        assertEquals(16, data.block00.size)
        // little-endian u64 of bytes 0x11..0x18
        assertEquals(0x1817161514131211UL.toLong(), data.word10)
        assertEquals(64, data.metadata64.size)
        assertEquals(0x75, data.flavor) // raw[0x74] = (0x74 + 1)
    }

    // ---- header assembly -----------------------------------------------------

    @Test
    fun anisetteHeadersUseRealOtpDerivation() {
        val metadata = ByteArray(60) { 0x11.toByte() }
        val mid = ByteArray(32) { 0x22.toByte() }
        val keychain = hex("000102030405060708090a0b0c0d0e0f")
        val now = 1_700_000_000_000L
        val anisette = ClearAdiAnisette(metadata, mid, ClearAnisetteProvider.FLAVOR_MAC, "1710631289", keychain, "MacBookPro18,1") { now }
        val headers = anisette.headers()
        assertEquals("UTC", headers["X-Apple-I-TimeZone"])
        assertEquals("en_US", headers["X-Apple-Locale"])
        assertEquals("1710631289", headers["X-Apple-I-MD-RINFO"])
        assertEquals("2023-11-14T22:13:20Z", headers["X-Apple-I-Client-Time"])
        assertEquals("00010203-0405-0607-0809-0a0b0c0d0e0f", headers["X-Mme-Device-Id"])
        assertEquals(Base64.getEncoder().encodeToString(mid), headers["X-Apple-I-MD-M"])
        // the OTP must be the real derivation: recompute and compare
        val otp = ClearAdiOtp.anisetteOtp(ClearAnisetteProvider.FLAVOR_MAC, metadata, mid, now / 1000)
        assertEquals(Base64.getEncoder().encodeToString(otp), headers["X-Apple-I-MD"])
        assertEquals(28, Base64.getDecoder().decode(headers["X-Apple-I-MD"]!!).size)
    }

    @Test
    fun appleRequestHeadersTranscribeBuildAppleRequest() {
        val provider = provider(ScriptedIdsHttp())
        val headers = provider.buildAppleRequestHeaders(1_700_000_000_000L)
        assertEquals("-10000", headers["X-Apple-Baa-E"])
        assertEquals("2", headers["X-Apple-Baa-Avail"])
        assertEquals("akd", headers["X-Apple-Client-App-Name"])
        assertEquals("en-US,en;q=0.9", headers["Accept-Language"])
        assertEquals("*/*", headers["Accept"])
        assertEquals("application/x-www-form-urlencoded", headers["Content-Type"])
        assertEquals("AKAuthenticationError:-7066|com.apple.devicecheck.error.baa:-10000", headers["X-Apple-Baa-UE"])
        assertEquals("-7066", headers["X-Apple-Host-Baa-E"])
        // build_apple_request formats %+ (+00:00); only get_headers rewrites to Z
        assertEquals("2023-11-14T22:13:20+00:00", headers["X-Apple-I-Client-Time"])
        assertEquals("00010203-0405-0607-0809-0a0b0c0d0e0f", headers["X-Mme-Device-Id"])
        assertEquals("akd-user-agent/1", headers["User-Agent"])
        // md_lu = sha256(keychain_identifier) hex
        val lu = java.security.MessageDigest.getInstance("SHA-256")
            .digest(hex("000102030405060708090a0b0c0d0e0f"))
        assertEquals(lu.joinToString("") { "%02x".format(it) }, headers["X-Apple-I-MD-LU"])
    }

    // ---- state round-trip + full scripted flow --------------------------------

    @Test
    fun provisionResultJsonRoundTrip() {
        val raw = ByteArray(0x78) { it.toByte() }
        val result = ClearAdiProvisionResult(ProvisionedData(raw), "1710631289")
        val restored = resultFromJson(resultToJson(result))
        assertContentEquals(raw, restored.provisionedData.raw)
        assertEquals("1710631289", restored.rinfo)
    }

    @Test
    fun provisionFlowsThroughScriptedHttp() = kotlinx.coroutines.runBlocking {
        val http = ScriptedIdsHttp()
        val store = MemoryStateStore()
        val provider = provider(http = http, store = store)
        val result = provider.ensureProvisioned()
        assertEquals(0x78, result.provisionedData.raw.size)
        assertEquals("1710631289", result.rinfo)
        // second call is served from the store without new HTTP traffic
        val callsAfterFirst = http.calls
        val second = provider.ensureProvisioned()
        assertEquals(callsAfterFirst, http.calls)
        assertContentEquals(result.provisionedData.raw, second.provisionedData.raw)
        assertTrue(store.saved!!.contains("provisioned_data"))
    }

    private fun provider(http: ScriptedIdsHttp, store: ClearAdiStateStore = MemoryStateStore()): ClearAnisetteProvider =
        ClearAnisetteProvider(
            http = http,
            stateStore = store,
            loginInfo = ClearAdiLoginInfo("akd-user-agent/1", "com.apple.mme/1 (MacBookPro18,1)"),
            rng = FixedRng(),
            cpimTailSeal = seal,
            finishSeed = ByteArray(16),
            keychainIdentifier = hex("000102030405060708090a0b0c0d0e0f"),
            clock = { 1_700_000_000_000L },
        )

    private class MemoryStateStore : ClearAdiStateStore {
        var saved: String? = null
        override fun save(json: String) { saved = json }
        override fun load(): String? = saved
    }

    /** Scripted GSA: lookup → start (spim) → finish (ptm/tk/rinfo), shaped like the reference. */
    private class ScriptedIdsHttp(private val tkSize: Int = 16) : IdsHttp {
        var calls = 0
        override fun close() {}
        override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse {
            calls++
            assertTrue(url.startsWith("https://gsa.apple.com/grandslam/GsService2/lookup"))
            assertTrue(headers.containsKey("X-Apple-Baa-E"))
            return IdsHttpResponse(
                200,
                emptyMap(),
                XmlPlist.encode(
                    mapOf(
                        "urls" to mapOf(
                            "midStartProvisioning" to "https://gsa.apple.com/start",
                            "midFinishProvisioning" to "https://gsa.apple.com/finish",
                        ),
                    ),
                ),
            )
        }
        override suspend fun put(url: String, headers: Map<String, String>, body: ByteArray, contentType: String) =
            throw UnsupportedOperationException()
        override suspend fun post(url: String, headers: Map<String, String>, body: ByteArray, contentType: String): IdsHttpResponse {
            calls++
            val bodyPlist = Plist.parse(body)
            return if (url.endsWith("/start")) {
                assertTrue(headers.containsKey("X-Apple-I-Client-Time"))
                assertBodyHasEmptyDicts(bodyPlist)
                IdsHttpResponse(
                    200,
                    emptyMap(),
                    XmlPlist.encode(
                        mapOf("Response" to mapOf("spim" to Base64.getEncoder().encodeToString(buildSpim()))),
                    ),
                )
            } else {
                // the cpim must be the base64 request body field
                @Suppress("UNCHECKED_CAST")
                val request = (bodyPlist as Map<String, Any?>)["request"] as Map<String, String>
                assertTrue(request.containsKey("cpim"))
                IdsHttpResponse(
                    200,
                    emptyMap(),
                    XmlPlist.encode(
                        mapOf(
                            "Response" to mapOf(
                                // 240 B ptm ⇒ 15 decrypt blocks ⇒ ≥ 0x78 ProvisionedData source
                                "ptm" to Base64.getEncoder().encodeToString(ByteArray(240)),
                                "tk" to Base64.getEncoder().encodeToString(ByteArray(tkSize)),
                                "X-Apple-I-MD-RINFO" to "1710631289",
                            ),
                        ),
                    ),
                )
            }
        }
        private fun assertBodyHasEmptyDicts(body: Any?) {
            @Suppress("UNCHECKED_CAST")
            val m = body as Map<String, Any?>
            assertEquals(0, (m["header"] as Map<*, *>).size)
            assertEquals(0, (m["request"] as Map<*, *>).size)
        }
    }

    private fun readBeU32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

    private fun readBeU64(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = (v shl 8) or (b[off + i].toLong() and 0xff)
        return v
    }
}

private fun buildSpim(field1: Int = 0, payload: ByteArray = ByteArray(240), tail: ByteArray = ByteArray(0)): ByteArray {
    val out = ByteArray(8 + payload.size + tail.size)
    out[0] = (field1 ushr 24).toByte(); out[1] = (field1 ushr 16).toByte()
    out[2] = (field1 ushr 8).toByte(); out[3] = field1.toByte()
    val len = payload.size
    out[4] = (len ushr 24).toByte(); out[5] = (len ushr 16).toByte()
    out[6] = (len ushr 8).toByte(); out[7] = len.toByte()
    payload.copyInto(out, 8)
    tail.copyInto(out, 8 + payload.size)
    return out
}
