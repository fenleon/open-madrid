package dev.fenn.imessage.engine

import java.io.IOException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

/** Offline HTTP round-trips against the minimal local server (no TLS needed for transport logic). */
class JavaNetIdsHttpTest {

    private var server: LocalHttpServer? = null

    @AfterTest
    fun tearDown() {
        server?.stop()
    }

    private fun startServer(handler: (LocalHttpServer.Request) -> LocalHttpServer.Response): Int {
        LocalHttpServer(handler).also { server = it; it.start() }
        return server!!.port
    }

    @Test
    fun `get carries headers and returns status body and lowercased headers`() = runBlocking {
        val port = startServer { request ->
            assertEquals("v1660", request.headers["x-protocol-version"])
            LocalHttpServer.Response(200, mapOf("X-Id-Status" to "ok"), "hello".toByteArray())
        }
        val response = JavaNetIdsHttp().get(
            "http://127.0.0.1:$port/ids",
            headers = mapOf("x-protocol-version" to "v1660"),
        )
        assertEquals(200, response.status)
        assertContentEquals("hello".toByteArray(), response.body)
        // Response header names are lower-cased (the [IdsHttpResponse] contract).
        assertEquals("ok", response.headers["x-id-status"])
    }

    @Test
    fun `post sends the body and content type and reads the response`() = runBlocking {
        val port = startServer { request ->
            assertContentEquals(byteArrayOf(1, 2, 3), request.body)
            assertEquals("application/x-apple-plist", request.headers["content-type"])
            LocalHttpServer.Response(201, body = request.body)
        }
        val response = JavaNetIdsHttp().post(
            "http://127.0.0.1:$port/post",
            headers = emptyMap(),
            body = byteArrayOf(1, 2, 3),
            contentType = "application/x-apple-plist",
        )
        assertEquals(201, response.status)
        assertContentEquals(byteArrayOf(1, 2, 3), response.body)
    }

    @Test
    fun `put works and error statuses carry the body`() = runBlocking {
        val port = startServer { request ->
            assertEquals("PUT", request.method)
            assertContentEquals(byteArrayOf(9, 8), request.body)
            LocalHttpServer.Response(500, body = request.body)
        }
        val response = JavaNetIdsHttp().put(
            "http://127.0.0.1:$port/put",
            headers = mapOf("h" to "v"),
            body = byteArrayOf(9, 8),
            contentType = "text/plain",
        )
        assertEquals(500, response.status)
        assertContentEquals(byteArrayOf(9, 8), response.body)
    }

    @Test
    fun `a server-side delay past the read timeout surfaces as an IOException`() = runBlocking {
        val port = startServer { _ ->
            Thread.sleep(2_000)
            LocalHttpServer.Response(200)
        }
        val http = JavaNetIdsHttp(requestTimeoutMs = 100)
        assertFailsWith<IOException> { http.get("http://127.0.0.1:$port/slow") }
        assertTrue(true)
    }

    @Test
    fun `apple trust factory builds without touching the network`() {
        // The factory exists so the app shell composes AppleTrust's pinned context without
        // touching SSLContext itself. No TLS server here — construction only.
        JavaNetIdsHttp.appleTrustClient()
    }
}
