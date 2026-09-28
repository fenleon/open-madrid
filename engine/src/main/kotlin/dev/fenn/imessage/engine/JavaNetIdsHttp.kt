package dev.fenn.imessage.engine

import dev.fenn.imessage.ids.AppleTrust
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.IdsHttpResponse
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * The production [IdsHttp] on the JDK/platform `HttpURLConnection` stack — zero new
 * dependencies, works on the JVM (tests) and on Android (app shell).
 *
 * Port note (task deviation, deliberate): the task named `java.net.http.HttpClient`, but
 * `java/net/http` is absent from android.jar (checked platforms android-34/-36) — the class
 * cannot compile into an Android library and would not run on the device. The platform's
 * `HttpsURLConnection` is the equivalent zero-dependency stack; everything else (constructor
 * shape, the SSLContext injection, the `appleTrustClient()` factory) follows the task.
 *
 * Redirects are never followed — a failed IDS call is the caller's decision (the
 * originating `AppleIdsHttp`'s posture). TLS: when [sslContext] is given, its socket factory
 * is applied per connection (callers pass `AppleTrust`'s pinned pool, §1.2 [CAP-IDSTLS]);
 * null keeps the platform default (tests' plain HTTP is untouched by TLS either way).
 */
class JavaNetIdsHttp(
    private val sslContext: SSLContext? = null,
    private val connectTimeoutMs: Int = 30_000,
    private val requestTimeoutMs: Int = 60_000,
) : IdsHttp {

    override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse =
        exchange("GET", url, headers, body = null, contentType = null)

    override suspend fun put(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse = exchange("PUT", url, headers, body, contentType)

    override suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse = exchange("POST", url, headers, body, contentType)

    override fun close() {}

    private suspend fun exchange(
        method: String,
        url: String,
        headers: Map<String, String>,
        body: ByteArray?,
        contentType: String?,
    ): IdsHttpResponse = withContext(Dispatchers.IO) {
        val connection = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = this@JavaNetIdsHttp.connectTimeoutMs
            readTimeout = requestTimeoutMs
            instanceFollowRedirects = false
            headers.forEach { (name, value) -> setRequestProperty(name, value) }
            if (body != null) {
                doOutput = true
                if (!contentType.isNullOrEmpty()) setRequestProperty("Content-Type", contentType)
                setFixedLengthStreamingMode(body.size)
            }
            (this as? HttpsURLConnection)?.let { https ->
                sslContext?.let { https.sslSocketFactory = it.socketFactory }
            }
        }
        try {
            if (body != null) connection.outputStream.use { it.write(body) }
            val status = connection.responseCode
            val responseHeaders = connection.headerFields
                .filterKeys { it != null }
                .entries.associate { (name, values) ->
                    name!!.lowercase() to values.joinToString(", ")
                }
            val responseBody = (if (status in 200..299) connection.inputStream else connection.errorStream)
                ?.use { it.readBytes() } ?: ByteArray(0)
            IdsHttpResponse(status, responseHeaders, responseBody)
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        /** Convenience factory: the IDS pinned-Apple-roots client of §1.2 [CAP-IDSTLS]. */
        fun appleTrustClient(
            connectTimeoutMs: Int = 30_000,
            requestTimeoutMs: Int = 60_000,
        ): JavaNetIdsHttp = JavaNetIdsHttp(
            sslContext = SSLContext.getInstance("TLS").apply {
                init(null, arrayOf(AppleTrust.defaultTrustManager()), null)
            },
            connectTimeoutMs = connectTimeoutMs,
            requestTimeoutMs = requestTimeoutMs,
        )
    }
}
