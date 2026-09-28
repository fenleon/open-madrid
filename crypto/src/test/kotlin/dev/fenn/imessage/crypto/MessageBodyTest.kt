package dev.fenn.imessage.crypto

import dev.fenn.imessage.codec.NativePlist
import dev.fenn.imessage.codec.NativePlistException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class MessageBodyTest {

    private fun fullBody() = MessageBody(
        text = "hello there",
        subject = "subj",
        participants = listOf("mailto:self@example.com", "mailto:peer@example.com"),
        richBody = "<msr><file></file></msr>",
        groupGuid = "guid-1",
        groupVersion = "8",
        protocolVersion = "1",
        propertiesVersion = 1L,
        threadRef = "r:0:0:5:uuid",
        screenEffect = "com.apple.messages.effect.confetti",
        displayName = "The Group",
        audio = true,
        expiringAudio = false,
        balloonId = "com.apple.messages.URLBalloonProvider",
        balloonPayload = byteArrayOf(1, 2, 3),
        balloonDownloadInfo = mapOf(
            "key" to "0x00deadbeef",
            "size" to 3L,
            "owner" to "owner",
            "URL" to "https://content.example.com/a",
            "signature" to "abc123",
        ),
        messageSummaryInfo = mapOf("amc" to 4L, "ams" to "source", "amb" to "balloon"),
        previousMessageUuid = ByteArray(16) { it.toByte() },
    )

    @Test
    fun versionsStayStringsPerSpec() {
        val raw = NativePlist.decode(fullBody().encode()) as Map<*, *>
        assertEquals("8", raw["gv"], "gv is the string \"8\" (spec §5.2)")
        assertEquals("1", raw["v"], "v is the string \"1\" (spec §5.2)")
    }

    @Test
    fun encodeEmitsExactlyTheRecordedKeys() {
        val raw = NativePlist.decode(fullBody().encode()) as Map<*, *>
        assertEquals(
            setOf("t", "s", "p", "x", "gid", "gv", "v", "pv", "tg", "iid", "n", "a", "e", "bid", "bp", "bpdi", "msi", "r"),
            raw.keys,
        )
    }

    @Test
    fun roundTripPreservesAllRecordedFields() {
        val back = MessageBody.decode(fullBody().encode())
        assertEquals("hello there", back.text)
        assertEquals("subj", back.subject)
        assertEquals(listOf("mailto:self@example.com", "mailto:peer@example.com"), back.participants)
        assertEquals("<msr><file></file></msr>", back.richBody)
        assertEquals("guid-1", back.groupGuid)
        assertEquals("8", back.groupVersion)
        assertEquals("1", back.protocolVersion)
        assertEquals(1L, back.propertiesVersion)
        assertEquals("r:0:0:5:uuid", back.threadRef)
        assertEquals("com.apple.messages.effect.confetti", back.screenEffect)
        assertEquals("The Group", back.displayName)
        assertEquals(true, back.audio)
        assertEquals(false, back.expiringAudio)
        assertEquals("com.apple.messages.URLBalloonProvider", back.balloonId)
        assertContentEquals(byteArrayOf(1, 2, 3), back.balloonPayload)
        assertEquals(5, back.balloonDownloadInfo?.size)
        assertEquals(3L, back.balloonDownloadInfo?.get("size"))
        assertEquals(3, back.messageSummaryInfo?.size)
        assertEquals("source", back.messageSummaryInfo?.get("ams"))
        assertContentEquals(ByteArray(16) { it.toByte() }, back.previousMessageUuid)
    }

    @Test
    fun sparseBodiesRoundTrip() {
        val back = MessageBody.decode(MessageBody(text = "typing", protocolVersion = "1").encode())
        assertEquals("typing", back.text)
        assertEquals("1", back.protocolVersion)
        assertEquals(null, back.participants)
    }

    @Test
    fun emptyBodyDecodesToAllNulls() {
        val back = MessageBody.decode(NativePlist.encode(emptyMap<String, Any?>()))
        assertEquals(MessageBody(), back.copy(previousMessageUuid = null, balloonPayload = null))
        assertEquals(null, back.text)
    }

    @Test
    fun nonStringParticipantFailsLoudly() {
        val bytes = NativePlist.encode(mapOf("p" to listOf(1L)))
        assertFailsWith<NativePlistException> { MessageBody.decode(bytes) }
    }

    @Test
    fun plainTextEncodesAsBinaryPlist() {
        val encoded = MessageBody(text = "plain").encode()
        assertTrue(encoded.size > 8 && encoded.copyOfRange(0, 8).decodeToString() == "bplist00", "inner plaintext is a binary plist (§4.1)")
    }
}
