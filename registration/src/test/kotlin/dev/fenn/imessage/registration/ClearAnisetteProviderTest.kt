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
 * Framing facts: new.asm/finish.asm plus the session-19f LIVE captures (WIRE-NOTES.md,
 * dev/clearadi/captures/). The scripted HTTP flow exercises everything up to the PTM gate —
 * faking a gate-valid PTM would need Apple's PTM encryptor, so the full-gate path is asserted
 * at the data level ([ProvisionedData.fromDecrypt]) instead.
 */
class ClearAnisetteProviderTest {

    private fun hex(s: String): ByteArray =
        ByteArray(s.length / 2) { ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte() }

    // ---- Spim parse ----------------------------------------------------------

    private fun spimBytes(field1: Int = 0, payload: ByteArray = ByteArray(240), tail: ByteArray = ByteArray(0)): ByteArray = buildSpim(field1, payload, tail)

    @Test
    fun spimParseExtractsFields() {
        val payload = ByteArray(240) { it.toByte() }
        val tail = ByteArray(99) { 0x55.toByte() } // the live Spim carries 99 trailing bytes
        val spim = Spim.parse(spimBytes(field1 = 0x01020304, payload = payload, tail = tail))
        assertEquals(0x01020304, spim.field1)
        assertEquals(240, spim.payloadLength)
        assertContentEquals(payload, spim.payload)
        assertContentEquals(tail, spim.trailing)
    }

    @Test
    fun spimParseRejectsShortPayloadAndTruncation() {
        // payload ≤ 59 B rejected (17efb33)
        assertFailsWith<SpimFormatException> { Spim.parse(spimBytes(payload = ByteArray(59))) }
        // truncated header
        assertFailsWith<SpimFormatException> { Spim.parse(ByteArray(3)) }
        // payload length beyond the buffer
        val b = spimBytes()
        b[4] = 0x00; b[5] = 0x00; b[6] = 0x01; b[7] = 0x00
        assertFailsWith<SpimFormatException> { Spim.parse(b) }
    }

    // ---- Cpim build ----------------------------------------------------------

    /** Deterministic RNG: draws are 0x10/0x20/0x30/0x40/0x50-filled (draw1, draw2, draw3, iv, tail12). */
    private class FixedRng : ClearAdiRng {
        var n = 0
        override fun draw(n: Int): ByteArray {
            val fill = when (++this.n) { 1 -> 0x10; 2 -> 0x20; 3 -> 0x30; 4 -> 0x40; else -> 0x50 }.toByte()
            return ByteArray(n) { fill }
        }
    }

    /**
     * The live wire tail: `[X 32][u32 BE 52][u32 BE 4][Y 52]` — the 60-byte
     * `[52][4][Y52]` group == the Spim's trailing[16:76] relayed verbatim (server material)
     * and **X (32 B) is the one TODO(live-capture) byte group**, zero-filled here.
     */
    private val seal = CpimTailSeal { spimTrailing, _, _ ->
        ByteArray(32) + spimTrailing.copyOfRange(16, 76)
    }

    @Test
    fun cpimShaTailSealMatchesPinnedFormula() {
        // session-19f continuation: X = SHA-256(encout ‖ spimMapSignature(trailing[0:16]) ‖ CONST24),
        // tail = X ‖ trailing[16:76] — verified byte-exact against two live runs (cap8/cap9).
        val trailing = ByteArray(99) { ((it * 7 + 3) and 0xff).toByte() }
        val encout = ByteArray(32) { ((it * 11 + 5) and 0xff).toByte() }
        val tail = CpimShaTailSeal.seal(trailing, encout, ByteArray(16))
        assertEquals(92, tail.size)
        assertContentEquals(
            hex(
                "342f120b8ed971980b7a4641822e648a4da000004a7e3116ee65a33a8999c2ab" +
                    "737a81888f969da4abb2b9c0c7ced5dce3eaf1f8ff060d141b222930373e454c535a61686f767d" +
                    "848b9299a0a7aeb5bcc3cad1d8dfe6edf4fb020910",
            ),
            tail,
        )
    }

    @Test
    fun cpimBuildMatchesLiveWireLayout() {
        val extra = ByteArray(10) { 0xAB.toByte() }
        val trailing = ByteArray(99) { (it + 1).toByte() }
        val session = ClearAdiProvision.initSession(ByteArray(240))
        val built = Cpim.build(FixedRng(), extra, -2L, 1_700_000_000L, session, ByteArray(240), trailing, seal)
        // outer: [u32 BE 5][iv 16][u32 BE 160][encout 160][tail 92]
        assertEquals(276, built.wire.size)
        assertEquals(5, readBe(built.wire, 0))
        assertContentEquals(ByteArray(16) { 0x40.toByte() }, built.iv)
        assertContentEquals(built.iv, built.wire.copyOfRange(4, 20))
        assertEquals(160, readBe(built.wire, 20))
        // plaintext rebuilt from the same draws → encout must match the real cipher
        val vec1 = ClearAdiProvision.encsec(ByteArray(32) { 0x20.toByte() })
        val plain = ByteArray(160)
        var p = 0
        p = putBe(plain, p, 32, 4)
        System.arraycopy(vec1, 0, plain, p, 32); p += 32
        p = putBe(plain, p, 32, 4)
        System.arraycopy(ByteArray(32) { 0x10.toByte() }, 0, plain, p, 32); p += 32 // draw1 = vec2 raw
        System.arraycopy(extra, 0, plain, p, extra.size); p += extra.size
        System.arraycopy(ByteArray(50) { 0x30.toByte() }, 0, plain, p, 50); p += 50 // blob = extra ‖ draw3
        p = putBe(plain, p, -2L, 8)
        p = putBe(plain, p, 1_700_000_000L, 4)
        p = putBe(plain, p, 1, 4)
        System.arraycopy(ByteArray(12) { 0x50.toByte() }, 0, plain, p, 12); p += 12
        val encout = ClearAdiProvision.encrypt(session, built.iv, plain)
        assertContentEquals(encout, built.wire.copyOfRange(24, 184))
        // the seal's relayed group comes from the Spim trailing
        assertContentEquals(trailing.copyOfRange(16, 76), built.wire.copyOfRange(216, 276))
        // draws surface for the finish side
        assertContentEquals(ByteArray(32) { 0x10.toByte() }, built.draw1)
        assertContentEquals(ByteArray(32) { 0x20.toByte() }, built.draw2)
        assertContentEquals(ByteArray(60) { 0x30.toByte() }, built.draw3)
    }

    @Test
    fun cpimBuildRejectsOversizeExtra() {
        assertFailsWith<IllegalArgumentException> {
            Cpim.build(FixedRng(), ByteArray(61), -2L, 0L, ByteArray(0x28F0), ByteArray(240), ByteArray(0), seal)
        }
    }

    // ---- Ptm parse (live-pinned layout) ---------------------------------------

    @Test
    fun ptmParsePinnedLayout() {
        val seed = ByteArray(16) { 0x11.toByte() }
        val payload = ByteArray(448) { 0x22.toByte() }
        val trailing = ByteArray(31) { 0x33.toByte() }
        val ptm = Ptm.parse(
            beBytes(4, 4) + seed + beBytes(448, 4) + payload + trailing,
        )
        assertEquals(4, ptm.field1)
        assertContentEquals(seed, ptm.seed)
        assertContentEquals(payload, ptm.payload)
        assertContentEquals(trailing, ptm.trailing)
        // payload length beyond the buffer
        val short = beBytes(4, 4) + seed + beBytes(999, 4)
        assertFailsWith<SpimFormatException> { Ptm.parse(short) }
        // truncated header
        assertFailsWith<SpimFormatException> { Ptm.parse(ByteArray(23)) }
    }

    @Test
    fun finishRejectsTkNot16Bytes() = kotlinx.coroutines.runBlocking {
        val http = ScriptedIdsHttp(tkSize = 15)
        val provider = provider(http = http)
        val ex = assertFailsWith<ClearAdiProvisioningException> { provider.provision() }
        assertTrue(ex.message!!.contains("tk not exactly 16 bytes"))
    }

    // ---- ProvisionedData assembly + gate ---------------------------------------

    private fun syntheticDecryptOut(draw1: ByteArray): ByteArray {
        val out = ByteArray(448)
        putBe(out, 0, 400, 4)
        for (i in 4 until 404) out[i] = i.toByte()
        draw1.copyInto(out, 408)
        return out
    }

    @Test
    fun provisionedDataAssemblesFromDecryptOutput() {
        val draw1 = ByteArray(32) { 0x10.toByte() }
        val draw2 = ByteArray(32) { 0x20.toByte() }
        val draw3 = ByteArray(60) { 0x30.toByte() }
        val out = syntheticDecryptOut(draw1)
        val data = ProvisionedData.fromDecrypt(out, draw1, draw2, draw3)
        assertEquals(400, data.metadata.size)
        assertEquals(25.toByte(), data.metadata[21])
        assertContentEquals(draw2, data.clientSecret)
        assertContentEquals(draw3, data.mid)
    }

    @Test
    fun provisionedDataRejectsGateMismatchAndShortOutput() {
        val draw1 = ByteArray(32) { 0x10.toByte() }
        val draw2 = ByteArray(32) { 0x20.toByte() }
        val draw3 = ByteArray(60) { 0x30.toByte() }
        val wrongEcho = syntheticDecryptOut(ByteArray(32) { 0xEE.toByte() })
        val ex = assertFailsWith<IllegalArgumentException> {
            ProvisionedData.fromDecrypt(wrongEcho, draw1, draw2, draw3)
        }
        assertTrue(ex.message!!.contains("PTM gate mismatch"))
        val ex2 = assertFailsWith<IllegalArgumentException> {
            ProvisionedData.fromDecrypt(ByteArray(100), draw1, draw2, draw3)
        }
        assertTrue(ex2.message!!.contains("too short"))
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
    fun provisionedAnisetteJsonRoundTrip() {
        val anisette = ProvisionedAnisette(
            clientSecret = ByteArray(32) { 1 },
            mid = ByteArray(60) { 2 },
            metadata = ByteArray(400) { 3 },
            rinfo = "1710631289",
            flavor = ClearAnisetteProvider.FLAVOR_MAC,
        )
        val restored = ProvisionedAnisette.fromJson(anisette.toJson())
        assertContentEquals(anisette.clientSecret, restored.clientSecret)
        assertContentEquals(anisette.mid, restored.mid)
        assertContentEquals(anisette.metadata, restored.metadata)
        assertEquals(anisette.rinfo, restored.rinfo)
        assertEquals(anisette.flavor, restored.flavor)
    }

    @Test
    fun provisionFlowsThroughScriptedHttpToTheGate() = kotlinx.coroutines.runBlocking {
        val http = ScriptedIdsHttp()
        val provider = provider(http = http)
        // the scripted PTM cannot echo the gate (faking that needs Apple's PTM encryptor),
        // so the live-shaped flow must fail exactly at the gate check
        val ex = assertFailsWith<IllegalArgumentException> { provider.provision() }
        assertTrue(ex.message!!.contains("PTM gate mismatch"))
        assertEquals(3, http.calls) // lookup + start + finish
    }

    @Test
    fun secondEnsureCallIsServedFromStore() = kotlinx.coroutines.runBlocking {
        val store = MemoryStateStore()
        store.save(
            ProvisionedAnisette(
                clientSecret = ByteArray(32) { 1 },
                mid = ByteArray(60) { 2 },
                metadata = ByteArray(400) { 3 },
                rinfo = "1710631289",
                flavor = ClearAnisetteProvider.FLAVOR_MAC,
            ).toJson(),
        )
        val provider = provider(http = ScriptedIdsHttp(), store = store)
        val first = provider.ensureProvisioned()
        assertEquals("1710631289", first.rinfo)
        val second = provider.ensureProvisioned()
        assertContentEquals(first.clientSecret, second.clientSecret)
    }

    private fun provider(http: ScriptedIdsHttp, store: ClearAdiStateStore = MemoryStateStore()): ClearAnisetteProvider =
        ClearAnisetteProvider(
            http = http,
            stateStore = store,
            loginInfo = ClearAdiLoginInfo("akd-user-agent/1", "com.apple.mme/1 (MacBookPro18,1)"),
            rng = FixedRng(),
            cpimTailSeal = seal,
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
                        mapOf("Response" to mapOf("spim" to Base64.getEncoder().encodeToString(buildSpim(tail = ByteArray(99))))),
                    ),
                )
            } else {
                // the cpim must be the base64 request body field
                @Suppress("UNCHECKED_CAST")
                val request = (bodyPlist as Map<String, Any?>)["request"] as Map<String, String>
                assertTrue(request.containsKey("cpim"))
                val cpim = Base64.getDecoder().decode(request["cpim"]!!)
                // outer shape: [u32 BE 5][iv 16][u32 BE 160][encout 160][tail 88]
                assertEquals(276, cpim.size)
                assertEquals(160, readBe(cpim, 20))
                IdsHttpResponse(
                    200,
                    emptyMap(),
                    XmlPlist.encode(
                        mapOf(
                            "Response" to mapOf(
                                // live-shaped: [u32 BE 4][seed 16][u32 BE 448][payload 448][tail 31]
                                "ptm" to Base64.getEncoder().encodeToString(
                                    beBytes(4, 4) + ByteArray(16) + beBytes(448, 4) + ByteArray(448) + ByteArray(31),
                                ),
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

}

private fun readBe(b: ByteArray, off: Int): Int =
    ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
        ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

private fun beBytes(v: Long, n: Int): ByteArray = ByteArray(n) { (v ushr (8 * (n - 1 - it))).toByte() }

private fun putBe(dst: ByteArray, off: Int, v: Long, n: Int): Int {
    for (i in 0 until n) dst[off + i] = (v ushr (8 * (n - 1 - i))).toByte()
    return off + n
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
