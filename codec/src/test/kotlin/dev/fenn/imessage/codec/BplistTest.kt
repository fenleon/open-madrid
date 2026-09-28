package dev.fenn.imessage.codec

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BplistTest {

    private val magic = "bplist00".toByteArray(Charsets.US_ASCII)

    private fun be(width: Int, value: Long) = ByteArray(width) { i ->
        (value ushr (8 * (width - 1 - i))).toByte()
    }

    private fun trailer(offWidth: Int, refWidth: Int, count: Long, top: Long, tableOffset: Long) =
        ByteArray(5) + byteArrayOf(0, offWidth.toByte(), refWidth.toByte()) +
            be(8, count) + be(8, top) + be(8, tableOffset)

    // -- known answer ------------------------------------------------------

    @Test
    fun knownAnswerSmallDict() {
        // {"hi": true} — hand-computed: obj0 dict@8 (D1 01 02), obj1 "hi"@11
        // (51 68 69), obj2 true@14 (09); offsets 08 0B 0E; table@15, file=50.
        val out = Bplist.encode(BpDict(mapOf(BpString("hi") to BpBool(true))))
        val expected = magic +
            byteArrayOf(0xD1.toByte(), 0x01, 0x02) +
            byteArrayOf(0x52.toByte(), 0x68, 0x69) +
            byteArrayOf(0x09) +
            byteArrayOf(0x08, 0x0B, 0x0E) +
            trailer(1, 1, 3, 0, 15)
        assertTrue(out.contentEquals(expected), "got ${out.toHex()}")
    }

    @Test
    fun knownAnswerDateMarker() {
        val out = Bplist.encode(BpDate(0.0))
        val expected = magic +
            byteArrayOf(0x33) + be(8, 0) +
            byteArrayOf(0x08) +
            trailer(1, 1, 1, 0, 17)
        assertTrue(out.contentEquals(expected), "got ${out.toHex()}")
    }

    // -- round trips -------------------------------------------------------

    @Test
    fun roundTripSimpleValues() {
        for (v in listOf(BpNull, BpBool(false), BpBool(true))) {
            assertEquals(v, Bplist.decode(Bplist.encode(v)))
        }
    }

    @Test
    fun roundTripIntWidths() {
        for (i in listOf(
            0L, 0xFFL, 0x100L, 0xFFFFL, 0x1_0000L, 0xFFFF_FFFFL,
            0x1_0000_0000L, Long.MAX_VALUE,
        )) {
            assertEquals(BpInt(i), Bplist.decode(Bplist.encode(BpInt(i))))
        }
        // widths: 1/2/4/8 bytes across the boundary values above
        assertEquals(0x10, Bplist.encode(BpInt(0xFFL))[8].toInt() and 0xFF)
        assertEquals(0x11, Bplist.encode(BpInt(0x100L))[8].toInt() and 0xFF)
        assertEquals(0x12, Bplist.encode(BpInt(0x1_0000L))[8].toInt() and 0xFF)
        assertEquals(0x13, Bplist.encode(BpInt(0x1_0000_0000L))[8].toInt() and 0xFF)
    }

    @Test
    fun negativeIntsAre8ByteTwosComplement() {
        for (i in listOf(-1L, -255L, -0x1_0000_0000L, Long.MIN_VALUE)) {
            assertEquals(BpInt(i), Bplist.decode(Bplist.encode(BpInt(i))))
        }
        val out = Bplist.encode(BpInt(-1L))
        assertEquals(0x13, out[8].toInt() and 0xFF)
        assertTrue(out.slice(9..16).all { it == 0xFF.toByte() }, out.toHex())
    }

    @Test
    fun roundTripRealDateDataStrings() {
        for (v in listOf(
            BpReal(3.14159),
            BpReal(0.0),
            BpDate(712025642.123),
            BpData(byteArrayOf()),
            BpData(byteArrayOf(0, 1, 2, 0xFF.toByte(), 0x7F)),
            BpString(""),
            BpString("hello"),
            BpString("café ☕ 𐍈"),
        )) {
            assertEquals(v, Bplist.decode(Bplist.encode(v)))
        }
    }

    @Test
    fun roundTripUidWidths() {
        for (u in listOf(
            0uL, 0xFFuL, 0x100uL, 0xFFFFuL, 0x1_0000uL, 0xFFFF_FFFFuL,
            0x1_0000_0000uL, ULong.MAX_VALUE,
        )) {
            assertEquals(BpUid(u), Bplist.decode(Bplist.encode(BpUid(u))))
        }
        // 1/2/4/8-byte payload per marker nibble 0..3
        assertEquals(0x80, Bplist.encode(BpUid(0x12uL))[8].toInt() and 0xFF)
        assertEquals(0x81, Bplist.encode(BpUid(0x1234uL))[8].toInt() and 0xFF)
        assertEquals(0x82, Bplist.encode(BpUid(0x1_2345uL))[8].toInt() and 0xFF)
        assertEquals(0x83, Bplist.encode(BpUid(0x1_2345_6789uL))[8].toInt() and 0xFF)
    }

    @Test
    fun roundTripNestedCollections() {
        val v = BpDict(
            linkedMapOf(
                BpString("array") to BpArray(
                    listOf(BpInt(1L), BpString("two"), BpData(byteArrayOf(3, 4)),
                        BpArray(listOf(BpBool(true))), BpNull)
                ),
                BpString("dict") to BpDict(
                    linkedMapOf(
                        BpString("date") to BpDate(100.5),
                        BpString("uid") to BpUid(0x4242uL),
                        BpInt(9L) to BpString("non-string key"),
                        BpInt(-7L) to BpArray(listOf(BpInt(-1L))),
                    )
                ),
                BpString("nested") to BpArray(
                    listOf(BpDict(linkedMapOf(BpString("x") to BpArray(listOf(BpInt(7L))))))
                ),
            )
        )
        assertEquals(v, Bplist.decode(Bplist.encode(v)))
    }

    // -- extended lengths (>14 elements / inline-count path) ----------------

    @Test
    fun extendedLengths() {
        val bigArray = BpArray((1..20).map { BpInt(it.toLong()) })
        assertEquals(bigArray, Bplist.decode(Bplist.encode(bigArray)))

        val longString = BpString("x".repeat(100))
        assertEquals(longString, Bplist.decode(Bplist.encode(longString)))

        val longData = BpData(ByteArray(300) { (it and 0xFF).toByte() })
        assertEquals(longData, Bplist.decode(Bplist.encode(longData)))

        val bigDict = BpDict((1..17).associate { BpString("k$it") to BpInt(it.toLong()) })
        assertEquals(bigDict, Bplist.decode(Bplist.encode(bigDict)))

        val huge = BpArray(listOf(bigArray, bigDict, BpString("y".repeat(20))))
        assertEquals(huge, Bplist.decode(Bplist.encode(huge)))
    }

    @Test
    fun utf16LengthIsCodeUnitsNotBytes() {
        // "a𐐷b": 4 UTF-16 code units but 8 bytes — marker 0x6n carries 4.
        val s = BpString("a𐐷b")
        assertEquals(4, s.value.length) // surrogate pair counts as 2 chars
        val out = Bplist.encode(s)
        assertEquals(0x64, out[8].toInt() and 0xFF) // 0x6n marker, count 4
        assertEquals(s, Bplist.decode(out))
    }

    @Test
    fun asciiStringUsesMarker5() {
        val out = Bplist.encode(BpString("abc"))
        assertEquals(0x53, out[8].toInt() and 0xFF)
        assertEquals(BpString("abc"), Bplist.decode(out))
    }

    // -- malformed input ----------------------------------------------------

    @Test
    fun rejectsBadMagic() {
        val bad = byteArrayOf(0x62, 0x70, 0x6C, 0x69, 0x73, 0x74, 0x30, 0x31) + ByteArray(32)
        assertFailsWith<BplistFormatException> { Bplist.decode(bad) }
    }

    @Test
    fun rejectsTruncatedTrailer() {
        val full = Bplist.encode(BpBool(true))
        for (cut in intArrayOf(0, 10, full.size - 1)) {
            assertFailsWith<BplistFormatException> { Bplist.decode(full.copyOfRange(0, cut)) }
        }
    }

    @Test
    fun rejectsOutOfRangeRef() {
        // handcrafted: array of 1 element whose ref (5) exceeds the object count (1)
        val bytes = magic +
            byteArrayOf(0xA1.toByte(), 0x05) +
            byteArrayOf(0x08) +
            trailer(1, 1, 1, 0, 10)
        assertFailsWith<BplistFormatException> { Bplist.decode(bytes) }
    }

    @Test
    fun rejectsTopIndexOutOfRange() {
        val bytes = magic +
            byteArrayOf(0x09) +
            byteArrayOf(0x08) +
            trailer(1, 1, 1, 7, 9)
        assertFailsWith<BplistFormatException> { Bplist.decode(bytes) }
    }

    @Test
    fun rejectsUnknownMarker() {
        val bytes = magic +
            byteArrayOf(0x70) +
            byteArrayOf(0x08) +
            trailer(1, 1, 1, 0, 9)
        assertFailsWith<BplistFormatException> { Bplist.decode(bytes) }
    }

    @Test
    fun rejectsNonAscii0x5String() {
        val bytes = magic +
            byteArrayOf(0x51.toByte(), 0xC3.toByte(), 0xA9.toByte()) + // é in UTF-8
            byteArrayOf(0x08) +
            trailer(1, 1, 1, 0, 11)
        assertFailsWith<BplistFormatException> { Bplist.decode(bytes) }
    }

    private fun ByteArray.toHex() = joinToString(" ") { "%02X".format(it) }
}
