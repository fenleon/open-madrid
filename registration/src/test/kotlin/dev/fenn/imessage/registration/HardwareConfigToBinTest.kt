package dev.fenn.imessage.registration

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The C56-c `session250` serialization ([HardwareConfiguration.toBin] — the closed
 * `HardwareConfig::to_bin` grammar, NAC-NOTES.md): synthetic vectors only.
 */
class HardwareConfigToBinTest {

    private fun config(
        serialEnc: ByteArray = byteArrayOf(1, 2, 3),
    ) = HardwareConfiguration(
        productName = "TestMac1,1",
        osBuildNumber = "25A1",
        platformSerial = "ABC123",
        platformUuid = "UUID-1",
        rootDiskUuid = "UUID-2",
        boardId = "Mac-ZZ",
        macAddress = byteArrayOf(0x00, 0x11, 0x22, 0x33, 0x44, 0x55),
        rom = byteArrayOf(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f),
        mlb = "MLB17CHARS000001",
        serialEnc = serialEnc,
        platformUuidEnc = byteArrayOf(4, 4),
        rootDiskUuidEnc = byteArrayOf(5, 5, 5, 5, 5),
        romEnc = byteArrayOf(6, 6, 6, 6, 6, 6, 6),
        mlbEnc = byteArrayOf(0xfe.toByte(), 0xff.toByte()),
    )

    private fun str(s: String): ByteArray =
        byteArrayOf((s.length + 1).toByte()) + s.toByteArray(Charsets.UTF_8) + byteArrayOf(0)

    private fun item(vararg bytes: Byte): ByteArray =
        byteArrayOf(bytes.size.toByte()) + bytes

    @Test
    fun toBinMatchesTheClosedGrammarByteForByte() {
        val expected = str("TestMac1,1") +
            // the MAC — raw 6 B, no length prefix
            byteArrayOf(0x00, 0x11, 0x22, 0x33, 0x44, 0x55) +
            str("ABC123") +
            str("UUID-1") +
            str("UUID-2") +
            str("Mac-ZZ") +
            str("25A1") +
            // the to_bin constant dword
            byteArrayOf(0x00, 0x03, 0x0b, 0x52) +
            // the seven binary items in Mac-Hardware-Info export field order (8..14);
            // the MLB item carries the ASCII bytes with NO trailing NUL
            item(1, 2, 3) +
            item(4, 4) +
            item(5, 5, 5, 5, 5) +
            item(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f) +
            item(6, 6, 6, 6, 6, 6, 6) +
            item(*"MLB17CHARS000001".toByteArray(Charsets.US_ASCII)) +
            item(0xfe.toByte(), 0xff.toByte())
        assertContentEquals(expected, config().toBin())
    }

    @Test
    fun aLongerMachineThanTheLiveCaptureSerializesAtItsOwnLength() {
        // The 250-B name is that capture machine's size — the grammar is length-agnostic.
        val bytes = config(serialEnc = ByteArray(200)).toBin()
        val constIdx = bytes.indices.indexOfFirst { i ->
            bytes.drop(i).take(4).toByteArray().contentEquals(HardwareConfiguration.TO_BIN_CONSTANT)
        }
        assertTrue(constIdx >= 0)
        // The 200-byte serialEnc item follows the constant: u8(200) ‖ 200 zero bytes.
        assertEquals(200.toByte(), bytes[constIdx + 4])
        // The remaining six items (3 + 6 + 7 + 8 + 17 + 3 bytes) close the buffer.
        assertEquals(constIdx + 4 + 1 + 200 + 44, bytes.size)
    }

    @Test
    fun stringBeyondTheU8PrefixFailsLoudly() {
        val long = HardwareConfiguration(
            productName = "M".repeat(300),
            osBuildNumber = "25A1",
            platformSerial = "S",
            platformUuid = "U",
            rootDiskUuid = "R",
            boardId = "Mac-ZZ",
            macAddress = ByteArray(6),
            rom = ByteArray(6),
            mlb = "MLB",
            serialEnc = ByteArray(1),
            platformUuidEnc = ByteArray(1),
            rootDiskUuidEnc = ByteArray(1),
            romEnc = ByteArray(1),
            mlbEnc = ByteArray(1),
        )
        val error = assertFailsWith<ValidationDataException> { long.toBin() }
        assertTrue(error.message!!.contains("u8 length prefix"))
    }

    @Test
    fun binaryItemBeyondTheU8PrefixFailsLoudly() {
        val config = config(serialEnc = ByteArray(256))
        val error = assertFailsWith<ValidationDataException> { config.toBin() }
        assertTrue(error.message!!.contains("u8 length prefix"))
    }
}
