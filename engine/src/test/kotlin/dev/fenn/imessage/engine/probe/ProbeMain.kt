package dev.fenn.imessage.engine.probe

import dev.fenn.imessage.codec.Plist
import dev.fenn.imessage.codec.stringKeyedDictOrNull
import dev.fenn.imessage.engine.JavaNetIdsHttp
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.security.cert.Certificate
import javax.security.auth.x500.X500Principal
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.runBlocking

/**
 * Host-side live-probe runner — EXPLICIT network use only, never run by `test`.
 * Invoke via `tools/build --force --dir imessage :engine:runProbe` (from /home/fenn/Repo/light-phone).
 *
 * Authorized probes (2026-09-28 go-ahead; GETs only, no registration/IDS/auth/GSA/albert hosts):
 *   1. IDS bag fetch      — GET init.ess.apple.com getBag?ix=3 over AppleTrust-pinned TLS.
 *   2. APNs bag fetch     — GET init-p01st.push.apple.com/bag over plain HTTP (§1.2).
 *   3. Courier handshake  — raw SSLSocket (AppleTrust, no client certificate) to
 *                           courier.push.apple.com on 5223 and 443; record what arrives after.
 *
 * Probes 1–2 diff the live bag key sets against the committed capture fixtures
 * (codec/src/test/resources/imessage/, 2026-09-10). Drift is reported, never failed.
 * Cert chains and signature blobs are never printed in full — sizes and SHA-256 digests only.
 */

private const val IDS_BAG_URL =
    "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3"
private const val APNS_BAG_URL = "http://init-p01st.push.apple.com/bag"
private const val COURIER_HOST = "courier.push.apple.com"
private const val READ_TIMEOUT_MS = 15_000

private val WATCHED_KEYS = listOf(
    "bag-expiry-timestamp",
    "max-uri-multi-query",
    "id-query-refresh-queued-query-interval",
)

fun main(args: Array<String>) = runBlocking {
    val fixtureDir = (args.getOrNull(0) ?: "codec/src/test/resources/imessage").trimEnd('/')

    println("=== PROBE 1: IDS bag (pinned TLS) ===")
    probeTls("init.ess.apple.com", 443, AppleTrustPools.ids)
    probeBag("IDS bag", IDS_BAG_URL, "$fixtureDir/ids-bag-2026-09-10.xml", expectInner = 405)

    println()
    println("=== PROBE 2: APNs bag (plain HTTP, §1.2) ===")
    probeBag("APNs bag", APNS_BAG_URL, "$fixtureDir/apns-bag-2026-09-10.xml", expectInner = 65)

    println()
    println("=== PROBE 3: courier TLS handshake (no client certificate) ===")
    probeCourier(5223)
    probeCourier(443)

    println()
    println("=== PROBES COMPLETE ===")
}

// -- probe 1/2 shared: bag fetch + shape + fixture diff -------------------------------------

private suspend fun probeBag(label: String, url: String, fixturePath: String, expectInner: Int) {
    try {
        val http = JavaNetIdsHttp.appleTrustClient()
        http.use {
            val response = it.get(url)
            println("$label: HTTP ${response.status}, content-type=${response.headers["content-type"]}, " +
                "body=${response.body.size} B, sha256=${response.body.sha256()}")
            if (response.status != 200) {
                println("$label: unexpected status — body head: ${response.body.decodeToString().take(200)}")
                return
            }
            val outer = stringKeyedDictOrNull(Plist.parse(response.body))
            if (outer == null) {
                println("$label: PARSE SHAPE MISMATCH — top level is not a string-keyed dict")
                return
            }
            println("$label: top-level keys = ${outer.keys.sorted()}")
            outer["signature"]?.let { sig ->
                if (sig is ByteArray) println("$label: signature blob: ${sig.size} B, sha256=${sig.sha256()}")
            }
            val embedded = outer["bag"]
            val inner: Map<String, Any?>? = when (embedded) {
                is ByteArray -> stringKeyedDictOrNull(Plist.parse(embedded))
                is Map<*, *> -> embedded.entries.associate { it.key.toString() to it.value }
                else -> null
            }
            if (inner == null) {
                println("$label: inner bag MISSING or not a dict (got ${typeNameOf(embedded)})")
                return
            }
            println("$label: inner-bag entries = ${inner.size} (fixture: $expectInner)")

            val fixtureBag = loadFixtureInnerBag(fixturePath)
            if (fixtureBag == null) {
                println("$label: fixture not readable at $fixturePath — key-set diff skipped")
            } else {
                diffKeySets(label, inner, fixtureBag)
            }
        }
    } catch (e: Exception) {
        println("$label: PROBE ERROR — ${e::class.java.name}: ${e.message}")
    }
}

private fun loadFixtureInnerBag(path: String): Map<String, Any?>? {
    val file = java.io.File(path)
    if (!file.exists()) return null
    val outer = stringKeyedDictOrNull(Plist.parse(file.readBytes())) ?: return null
    val embedded = outer["bag"] ?: return stringKeyedDictOrNull(outer)
    return when (embedded) {
        is ByteArray -> stringKeyedDictOrNull(Plist.parse(embedded))
        is Map<*, *> -> embedded.entries.associate { it.key.toString() to it.value }
        else -> null
    }
}

private fun diffKeySets(label: String, live: Map<String, Any?>, fixture: Map<String, Any?>) {
    val added = live.keys - fixture.keys
    val removed = fixture.keys - live.keys
    println("$label: keys added since fixture   (${added.size}): ${added.sorted()}")
    println("$label: keys removed since fixture (${removed.size}): ${removed.sorted()}")

    val changed = live.keys.intersect(fixture.keys).filter { key -> !valuesEqual(live[key], fixture[key]) }
    println("$label: values changed on (${changed.size}) shared keys: ${changed.sorted()}")

    for (key in WATCHED_KEYS) {
        println("$label: $key live=${live[key]} fixture=${fixture[key]}")
    }
}

/** Structural equality across the plist-native types (bytes compared by content). */
private fun valuesEqual(a: Any?, b: Any?): Boolean = when {
    a is ByteArray && b is ByteArray -> a.contentEquals(b)
    a is List<*> && b is List<*> -> a.size == b.size && a.zip(b).all { (x, y) -> valuesEqual(x, y) }
    a is Map<*, *> && b is Map<*, *> -> a.size == b.size &&
        a.keys.all { b.containsKey(it) && valuesEqual(a[it], b[it]) }
    else -> a == b
}

private fun typeNameOf(value: Any?): String = value?.let { it::class.java.simpleName } ?: "null"

// -- probe 1/3 shared: raw TLS handshake + post-handshake read -------------------------------

private fun probeTls(host: String, port: Int, trustManager: TrustManager) {
    try {
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trustManager), null) }
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            socket.soTimeout = READ_TIMEOUT_MS
            socket.connect(InetSocketAddress(host, port), READ_TIMEOUT_MS)
            socket.startHandshake()
            val session = socket.session
            println("TLS $host:$port — handshake COMPLETE: protocol=${session.protocol}, " +
                "cipher=${session.cipherSuite}, peer certs:")
            describeCerts(session.peerCertificates.toList())
        } finally {
            socket.close()
        }
    } catch (e: Exception) {
        println("TLS $host:$port — handshake FAILED: ${e::class.java.name}: ${e.message}")
    }
}

private fun describeCerts(certs: List<Certificate>) {
    certs.forEachIndexed { index, cert ->
        if (cert is X509Certificate) {
            val cn = cert.subjectX500Principal.getName(X500Principal.CANONICAL)
                .substringAfter("cn=").substringBefore(",")
            println("  [$index] len=${cert.encoded.size} B, sha256=${cert.encoded.sha256()}, subject CN=$cn")
        } else {
            println("  [$index] len=${cert.encoded.size} B (non-X.509)")
        }
    }
}

private fun probeCourier(port: Int) {
    try {
        val context = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(AppleTrustPools.courier), null)
        }
        val socket = context.socketFactory.createSocket() as SSLSocket
        try {
            socket.soTimeout = READ_TIMEOUT_MS
            socket.connect(InetSocketAddress(COURIER_HOST, port), READ_TIMEOUT_MS)
            socket.startHandshake()
            val session = socket.session
            println("courier:$port — handshake COMPLETE: protocol=${session.protocol}, " +
                "cipher=${session.cipherSuite}")
            describeCerts(session.peerCertificates.toList())

            // No HTTP request, no APNs frame, no client certificate — just listen.
            val buffer = ByteArray(256)
            val start = System.currentTimeMillis()
            val read = try {
                socket.getInputStream().read(buffer)
            } catch (e: java.net.SocketTimeoutException) {
                -2
            }
            val elapsed = System.currentTimeMillis() - start
            when {
                read > 0 -> println("courier:$port — after handshake: $read B arrived in ${elapsed} ms: " +
                    buffer.copyOf(read).toHexString())
                read == -1 -> println("courier:$port — after handshake: peer CLOSED the stream " +
                    "(read returned -1) after ${elapsed} ms — no data, no TLS alert observed")
                read == -2 -> println("courier:$port — after handshake: nothing arrived within " +
                    "$READ_TIMEOUT_MS ms (read timeout, connection still open)")
                else -> println("courier:$port — after handshake: unexpected read result $read")
            }
            try {
                socket.close()
                println("courier:$port — local close: clean")
            } catch (e: Exception) {
                println("courier:$port — local close error: ${e::class.java.name}: ${e.message}")
            }
        } catch (e: javax.net.ssl.SSLException) {
            println("courier:$port — TLS-level failure after/during handshake: " +
                "${e::class.java.name}: ${e.message}")
        } finally {
            runCatching { socket.close() }
        }
    } catch (e: Exception) {
        println("courier:$port — PROBE ERROR: ${e::class.java.name}: ${e.message}")
    }
}

// -- AppleTrust pools (same construction the engine's factories use) -------------------------

private object AppleTrustPools {
    val ids: X509TrustManager by lazy { dev.fenn.imessage.ids.AppleTrust.defaultTrustManager() }
    val courier: X509TrustManager by lazy { dev.fenn.imessage.ids.AppleTrust.courierTrustManager() }
}

// -- small helpers ---------------------------------------------------------------------------

private fun ByteArray.sha256(): String =
    MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { "%02x".format(it) }

private fun ByteArray.toHexString(): String = take(64)
    .joinToString(" ") { "%02x".format(it) } + if (size > 64) " …(${size} B total)" else ""
