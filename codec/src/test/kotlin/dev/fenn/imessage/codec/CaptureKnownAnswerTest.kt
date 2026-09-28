package dev.fenn.imessage.codec

import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Known-answer vectors from REAL Apple wire bytes (own mitmproxy captures, 2026-09-10).
 * Provenance is recorded per test by capture filename. All embedded fixtures are public
 * static Apple files (the IDS bag, the APNs bag, the CDN validation-certificate plist) —
 * scanned for personal data before committing: no handles, tokens, device identifiers or
 * account material (grep hits for `tel:`/`mailto:`/`X-Apple-*`/UDID-like strings are 0).
 * Private capture material (validation-request.bin and friends) is NOT committed — its
 * structure lives in :registration's ValidationRequestStructureTest as digest + layout only.
 */
class CaptureKnownAnswerTest {

    private fun resource(name: String): ByteArray =
        javaClass.getResourceAsStream("/imessage/$name")!!.readBytes()

    // -- ids-bag-2026-09-10.xml: GET init.ess.apple.com getBag?ix=3 response ----------------

    @Test
    fun `real ids bag decodes with the recorded top-level shape`() {
        val outer = XmlPlist.decode(resource("ids-bag-2026-09-10.xml")) as Map<*, *>
        // [CAP-BAG]: the response is a plist with `signature`, `certs` and `bag` keys.
        assertEquals(setOf("signature", "certs", "bag"), outer.keys)
        assertIs<ByteArray>(outer["signature"])
        assertTrue((outer["signature"] as ByteArray).size >= 200, "an RSA signature blob")
        val certs = assertIs<List<*>>(outer["certs"])
        assertTrue(certs.isNotEmpty() && certs.all { it is ByteArray })
        assertIs<ByteArray>(outer["bag"])
    }

    @Test
    fun `real ids bag embedded dictionary has 405 entries with the recorded endpoint urls`() {
        val outer = XmlPlist.decode(resource("ids-bag-2026-09-10.xml")) as Map<*, *>
        val bag = XmlPlist.decode(outer["bag"] as ByteArray) as Map<*, *>
        // [CAP-BAG]: "the inner bag a flat dictionary of 405 entries".
        assertEquals(405, bag.size)
        val expected = mapOf(
            "id-register" to "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register",
            "id-query" to "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query",
            "id-authenticate-ds-id" to
                "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS",
            "id-validation-cert" to "http://static.ess.apple.com/identity/validation/cert-1.0.plist",
            "id-initialize-validation" to
                "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation",
            "id-get-handles" to "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles",
            "id-authenticate-phone-number" to
                "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/authenticatePhoneNumber",
        )
        expected.forEach { (key, url) -> assertEquals(url, bag[key], key) }
        // The bag is not string-valued throughout — typed scalars ride along (finding, see
        // the class KDoc): ints, bools, reals and lists of strings.
        assertEquals(28800L, bag["id-query-refresh-queued-query-interval"]) // §1.2's recorded 8 h scalar
        assertEquals(false, bag["vc-disaster-mode"])
        assertEquals(1789652036030L, bag["bag-expiry-timestamp"])
        assertEquals(0.4, bag["vc-adaptive-learning-A"])
        assertEquals(listOf("appleid@id.apple.com", "appleid@apple.com"), bag["ds-vetting-email-from"])
    }

    @Test
    fun `real ids bag inner dictionary round-trips through the xml writer value-exactly`() {
        val outer = XmlPlist.decode(resource("ids-bag-2026-09-10.xml")) as Map<*, *>
        val bag = XmlPlist.decode(outer["bag"] as ByteArray) as Map<*, *>
        // Apple's indentation differs from ours, so the comparison is on decoded values,
        // not bytes: encode → decode must be the identity on all 405 entries.
        val roundTripped = XmlPlist.decode(XmlPlist.encode(bag)) as Map<*, *>
        assertEquals(bag, roundTripped)
        assertEquals(405, roundTripped.size)
    }

    // -- apns-bag-2026-09-10.xml: GET init-p01st.push.apple.com/bag response -----------------

    @Test
    fun `real apns bag decodes with the recorded courier endpoint values`() {
        val outer = XmlPlist.decode(resource("apns-bag-2026-09-10.xml")) as Map<*, *>
        assertEquals(setOf("signature", "certs", "bag"), outer.keys)
        val bag = XmlPlist.decode(outer["bag"] as ByteArray) as Map<*, *>
        // §1.2/§3.1 record exactly two keys; the capture shows a 65-entry typed config (finding).
        assertEquals(65, bag.size)
        assertEquals("courier.push.apple.com", bag["APNSCourierHostname"])
        assertEquals(50L, bag["APNSCourierHostcount"])
    }

    // -- validation-cert-1.0.plist: CDN static object, the id-validation-cert GET body --------

    /**
     * §1.2's recorded container: a `cert` blob of 2385 bytes = `01 02` + two
     * (4-byte big-endian length, DER certificate) segments — the step-1 cert container
     * shape. Both segments are public Apple CA certificates (validated below by subject).
     */
    @Test
    fun `validation cert blob carries the 01 02 two-segment der container`() {
        val outer = XmlPlist.decode(resource("validation-cert-1.0.plist")) as Map<*, *>
        assertEquals(setOf("cert"), outer.keys)
        val blob = assertIs<ByteArray>(outer["cert"])
        assertEquals(2385, blob.size)
        assertEquals(0x01, blob[0].toInt())
        assertEquals(0x02, blob[1].toInt())

        val l1 = ((blob[2].toInt() and 0xFF) shl 24) or ((blob[3].toInt() and 0xFF) shl 16) or
            ((blob[4].toInt() and 0xFF) shl 8) or (blob[5].toInt() and 0xFF)
        assertEquals(1046, l1)
        val seg1 = blob.copyOfRange(6, 6 + l1)
        val off = 6 + l1
        val l2 = ((blob[off].toInt() and 0xFF) shl 24) or ((blob[off + 1].toInt() and 0xFF) shl 16) or
            ((blob[off + 2].toInt() and 0xFF) shl 8) or (blob[off + 3].toInt() and 0xFF)
        assertEquals(1329, l2)
        assertEquals(2385, off + 4 + l2, "the two segments account for the whole blob")
        val seg2 = blob.copyOfRange(off + 4, off + 4 + l2)

        val factory = CertificateFactory.getInstance("X.509")
        val c1 = factory.generateCertificate(ByteArrayInputStream(seg1)) as java.security.cert.X509Certificate
        val c2 = factory.generateCertificate(ByteArrayInputStream(seg2)) as java.security.cert.X509Certificate
        val cn = { c: java.security.cert.X509Certificate ->
            c.subjectX500Principal.getName(X500Principal.CANONICAL)
                .substringAfter("cn=").substringBefore(",")
        }
        // Both are public Apple CAs — the archived CDN object's known intermediates.
        assertEquals("apple system integration certification authority", cn(c1))
        assertEquals("drm technologies a01", cn(c2))
    }

    @Test
    fun `binary codec rejects the xml captures by magic`() {
        // The sweep of all 2026-09-10 capture files found zero bplist00 bodies — every
        // captured plist is XML. The binary decoder must not accept these files.
        for (name in listOf("ids-bag-2026-09-10.xml", "apns-bag-2026-09-10.xml")) {
            assertFailsWith<BplistFormatException> { Bplist.decode(resource(name)) }
        }
    }

    @Test
    fun `plist format dispatch routes the real captures to the xml codec`() {
        // Plist.parse is the entry point the IDS bag fetcher uses; the real bags must
        // reach the inner dictionary through it (they carry a DOCTYPE + XML declaration).
        val outer = Plist.parse(resource("ids-bag-2026-09-10.xml")) as Map<*, *>
        assertEquals(setOf("signature", "certs", "bag"), outer.keys)
        val apns = Plist.parse(resource("apns-bag-2026-09-10.xml")) as Map<*, *>
        assertEquals(setOf("signature", "certs", "bag"), apns.keys)
    }
}
