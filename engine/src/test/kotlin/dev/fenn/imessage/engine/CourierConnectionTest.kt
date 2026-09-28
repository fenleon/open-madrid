package dev.fenn.imessage.engine

import dev.fenn.imessage.courier.CourierClient
import dev.fenn.imessage.ids.AppleTrust
import java.net.ServerSocket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

/** What's mockable without a TLS server: lifecycle states and the not-connected guard. */
class CourierConnectionTest {

    /** A local port with no listener — TCP connect fails fast, no network, no TLS. */
    private fun closedPort(): Int = ServerSocket(0).use { it.localPort }

    private fun connection(port: Int) = CourierConnection(
        CourierClient.Config("courier.push.apple.com", port = port, backoffCapSecs = 1),
        trustManagers = arrayOf(AppleTrust.courierTrustManager()),
    )

    @Test
    fun `starts disconnected and reconnects when nothing listens then stops cleanly`() = runBlocking {
        val connection = connection(closedPort())
        assertEquals(CourierConnection.State.DISCONNECTED, connection.state.value)
        connection.start(object : CourierClient.Handler {})
        try {
            // The connect attempt fails (nothing listens) — the loop retries with backoff.
            withTimeout(2_000) {
                while (connection.state.value == CourierConnection.State.DISCONNECTED) delay(20)
            }
            assertEquals(CourierConnection.State.CONNECTING, connection.state.value)
        } finally {
            connection.stop()
        }
        assertEquals(CourierConnection.State.DISCONNECTED, connection.state.value)
        connection.close()
    }

    @Test
    fun `sending before a connection exists fails loudly`() {
        val connection = connection(closedPort())
        assertFailsWith<java.io.IOException> {
            connection.sendFrame(byteArrayOf(12, 0, 0, 0, 0))
        }
    }
}
