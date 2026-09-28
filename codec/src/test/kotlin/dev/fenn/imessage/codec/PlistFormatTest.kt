package dev.fenn.imessage.codec

import dev.fenn.imessage.codec.Bplist
import dev.fenn.imessage.codec.NativePlist
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PlistFormatTest {

    private val xml = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>"

    @Test
    fun binaryMagicDispatchesToTheBinaryCodec() {
        val binary = NativePlist.encode(mapOf("a" to 1L))
        assertEquals(mapOf("a" to 1L), Plist.parse(binary))
    }

    @Test
    fun xmlDeclarationDispatchesToTheXmlCodec() {
        assertEquals(mapOf("a" to 1L), Plist.parse(xml.toByteArray()))
    }

    @Test
    fun xmlWithoutDeclarationDispatchesOnThePlistRoot() {
        assertEquals(
            mapOf("a" to 1L),
            Plist.parse("<plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>".toByteArray()),
        )
    }

    @Test
    fun bomAndLeadingWhitespaceAreSkippedBeforeDispatching() {
        val bom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())
        assertEquals(mapOf("a" to 1L), Plist.parse(bom + xml.toByteArray()))
        // Whitespace may precede a <plist> root (a declaration must stay first, as XML requires).
        val noDeclaration = "<plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist>"
        assertEquals(mapOf("a" to 1L), Plist.parse("\n\t $noDeclaration".toByteArray()))
    }

    @Test
    fun garbageThrows() {
        assertFailsWith<PlistFormatException> { Plist.parse(ByteArray(0)) }
        assertFailsWith<PlistFormatException> { Plist.parse("not a plist at all.......".toByteArray()) }
    }

    // The binary codec's own exception type stays catchable as the shared top-level one.
    @Test
    fun binaryFormatExceptionIsTheSharedType() {
        assertFailsWith<PlistFormatException> { Bplist.decode("not a plist at all.......".toByteArray()) }
        assertFailsWith<BplistFormatException> { Bplist.decode(ByteArray(0)) }
    }

    @Test
    fun xmlBodyThatIsNotAPlistThrowsTheXmlCodecError() {
        assertFailsWith<PlistFormatException> { Plist.parse("<?xml version=\"1.0\"?><html/>".toByteArray()) }
    }
}
