package dev.fenn.imessage.ids

import java.io.Closeable
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import java.io.ByteArrayInputStream
import java.security.KeyStore
import javax.net.ssl.SSLContext

/** One IDS HTTP round trip: status, response headers (names lower-cased), raw body bytes. */
class IdsHttpResponse(val status: Int, val headers: Map<String, String>, val body: ByteArray)

/**
 * The IDS HTTP seam. Tests script responses through it; the production client (ktor/OkHttp
 * in the originating repo) was not ported into this module — see the port note on this file.
 * Header names are lower-cased in [IdsHttpResponse.headers] so callers compare
 * case-insensitively without worrying about the server's casing.
 */
interface IdsHttp : Closeable {

    suspend fun get(url: String, headers: Map<String, String> = emptyMap()): IdsHttpResponse

    suspend fun put(
        url: String,
        headers: Map<String, String> = emptyMap(),
        body: ByteArray,
        contentType: String = "",
    ): IdsHttpResponse

    suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse

    override fun close() {}
}

/**
 * The Apple-root trust pool of spec §1.2/§3.1: IDS HTTPS requests pin Apple roots and never
 * the system store ([CAP-IDSTLS]: neither root is served on the wire, and the unanchored
 * chain is rejected by the system store). The default pool is the two embedded roots —
 * `Apple Root CA - G3` (anchors the init.ess chain) and `Apple Root CA` (anchors the
 * query.ess chain) — staged as DER under `resources/imessage/`. Roots only, never
 * leaves/intermediates; a chain that does not terminate in one of them must fail loudly.
 */
object AppleTrust {

    private val ROOT_RESOURCES = listOf("/imessage/AppleRootCA-G3.cer", "/imessage/AppleRootCA.cer")

    /**
     * The courier anchor of spec §3.1 [CAP-COURIERTLS]: the courier chain terminates at the
     * publicly-trusted Comodo root `AAA Certificate Services` (not an Apple root) — the root
     * itself is never served on the wire, so the pool must embed it. Pin roots only; the
     * courier leaf rotates every ~90 days.
     */
    const val COURIER_ROOT_RESOURCE = "/imessage/AAACertificateServices.cer"

    /**
     * The packed-format courier chain's intermediate anchor (spec §3.2, C19 closed in rev 26):
     * with the `apns-pack-v1` ALPN the server serves leaf ← `Apple Server Authentication CA`
     * ← Apple Root CA, and the working client pins the INTERMEDIATE itself (observed on the
     * wire 2026-10-03; the same CA the albert activation pool's chain passes through).
     */
    const val COURIER_PACKED_ANCHOR_RESOURCE = "/imessage/AppleServerAuthenticationCA.cer"

    /** The default pool: the two embedded Apple roots (spec §1.2 [CAP-IDSTLS]). */
    fun defaultTrustManager(): X509TrustManager = trustManager(*embeddedRootDers())

    /**
     * The courier pool: the `AAA Certificate Services` root (§3.1 [CAP-COURIERTLS] — the
     * no-ALPN ECC chain) plus the `Apple Server Authentication CA` intermediate (the pack-v1
     * RSA chain the ALPN selects; §3.2 C19, rev 26).
     */
    fun courierTrustManager(): X509TrustManager = trustManager(
        embeddedRoot(COURIER_ROOT_RESOURCE),
        embeddedRoot(COURIER_PACKED_ANCHOR_RESOURCE),
    )

    /** A socket factory whose only trust anchor is [trustManager]. */
    fun sslSocketFactory(trustManager: X509TrustManager): SSLSocketFactory =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }.socketFactory

    private fun embeddedRoot(path: String): ByteArray =
        AppleTrust::class.java.getResourceAsStream(path)?.use { it.readBytes() }
            ?: throw IllegalStateException("embedded root $path missing from resources")

    private fun embeddedRootDers(): Array<ByteArray> = ROOT_RESOURCES.map { embeddedRoot(it) }.toTypedArray()

    /** A trust manager whose only anchors are [certificatesDer] (DER X.509, any count). */
    fun trustManager(vararg certificatesDer: ByteArray): X509TrustManager {
        require(certificatesDer.isNotEmpty()) { "at least one anchor certificate is required" }
        val factory = java.security.cert.CertificateFactory.getInstance("X.509")
        val store = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        certificatesDer.forEachIndexed { i, der ->
            store.setCertificateEntry("apple-anchor-$i", factory.generateCertificate(ByteArrayInputStream(der)))
        }
        val managers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            .apply { init(store) }
            .trustManagers
        return managers.filterIsInstance<X509TrustManager>().firstOrNull()
            ?: throw IllegalStateException("${TrustManagerFactory.getDefaultAlgorithm()} returned no X509TrustManager")
    }
}

// Port note: the originating repo's ktor/OkHttp implementation of [IdsHttp]
// (`AppleIdsHttp`, redirects and retries off, optional pinned trust manager per spec §1.2
// [CAP-IDSTLS]) was not ported — the HTTP stack deps are not in this repo's catalog yet.
// [IdsHttp] itself and the scripted test doubles cover the seam; port the client when the
// network module lands.
