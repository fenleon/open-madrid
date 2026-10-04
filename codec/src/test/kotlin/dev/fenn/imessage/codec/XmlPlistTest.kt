package dev.fenn.imessage.codec

import dev.fenn.imessage.codec.PlistDate
import dev.fenn.imessage.codec.BpUid
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class XmlPlistTest {

    // One document exercising every element the reader must know. The declaration, DOCTYPE,
    // comment and processing instruction are decoration the reader has to skip.
    private val sample = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <!-- a comment -->
        <?some-processing-instruction value?>
        <plist version="1.0">
        <dict>
          <key>name</key>
          <string>light phone</string>
          <key>count</key>
          <integer>42</integer>
          <key>ratio</key>
          <real>1.5</real>
          <key>yes</key>
          <true/>
          <key>no</key>
          <false/>
          <key>blob</key>
          <data>AQIDBA==</data>
          <key>wrapped</key>
          <data>
            BQYH
            CA==
          </data>
          <key>when</key>
          <date>2023-11-14T22:13:20Z</date>
          <key>list</key>
          <array>
            <string>a</string>
            <integer>7</integer>
            <array><string>inner</string></array>
          </array>
          <key>nested</key>
          <dict>
            <key>inner</key>
            <string>deep</string>
          </dict>
        </dict>
        </plist>
    """.trimIndent().toByteArray()

    @Suppress("UNCHECKED_CAST")
    private fun decodeSample(): Map<String, Any?> = XmlPlist.decode(sample) as Map<String, Any?>

    @Test
    fun decodesEveryElementTypeToTheBinaryPlistMapping() {
        val v = decodeSample()
        assertEquals("light phone", v["name"])
        assertEquals(42L, v["count"])
        assertEquals(1.5, v["ratio"])
        assertEquals(true, v["yes"])
        assertEquals(false, v["no"])
        assertContentEquals(byteArrayOf(1, 2, 3, 4), v["blob"] as ByteArray)
        assertEquals(PlistDate(1_700_000_000_000L), v["when"])
        assertEquals(mapOf("inner" to "deep"), v["nested"])
    }

    @Test
    fun skipsWhitespaceInsideData() {
        assertContentEquals(byteArrayOf(5, 6, 7, 8), decodeSample()["wrapped"] as ByteArray)
    }

    @Test
    fun arrayHoldsNestedValues() {
        val list = decodeSample()["list"] as List<*>
        assertEquals(3, list.size)
        assertEquals("a", list[0])
        assertEquals(7L, list[1])
        assertEquals(listOf("inner"), list[2])
    }

    @Test
    fun dictKeepsDocumentOrder() {
        assertEquals(
            listOf(
                "name", "count", "ratio", "yes", "no", "blob", "wrapped", "when", "list", "nested",
            ),
            decodeSample().keys.toList(),
        )
        assertEquals(listOf("inner"), (decodeSample()["nested"] as Map<*, *>).keys.toList())
    }

    @Test
    fun bareTopLevelValueWithoutDict() {
        assertEquals("solo", XmlPlist.decode("<plist version=\"1.0\"><string>solo</string></plist>".toByteArray()))
        assertEquals(11L, XmlPlist.decode("<plist><integer>11</integer></plist>".toByteArray()))
    }

    @Test
    fun doctypeAndEntityReferencesNeverReachTheFilesystem() {
        val xml = """
            <?xml version="1.0"?>
            <!DOCTYPE plist [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <plist version="1.0"><dict><key>leak</key><string>&xxe;</string></dict></plist>
        """.trimIndent()
        @Suppress("UNCHECKED_CAST")
        val v = XmlPlist.decode(xml.toByteArray()) as Map<String, Any?>
        assertFalse("${v["leak"]}".contains("root:"), "external entity was resolved")
    }

    @Test
    fun malformedInputFails() {
        val failures = listOf(
            ByteArray(0),
            "<plist>".toByteArray(),
            "<notplist><string>x</string></notplist>".toByteArray(),
            "<plist><string>a</string><string>b</string></plist>".toByteArray(),
            "<plist><dict><key>a</key></dict></plist>".toByteArray(), // odd child count
            "<plist><dict><string>a</string><string>b</string></dict></plist>".toByteArray(), // not a <key>
            "<plist><dict><key>a</key><widget/></dict></plist>".toByteArray(),
            "<plist><dict><key>a</key><integer>not a number</integer></dict></plist>".toByteArray(),
            "<plist><dict><key>a</key><real>nope</real></dict></plist>".toByteArray(),
            "<plist><dict><key>a</key><data>!!!</data></dict></plist>".toByteArray(),
            "<plist><dict><key>a</key><date>yesterday</date></dict></plist>".toByteArray(),
            "<plist><key>a</key></plist>".toByteArray(),
        )
        failures.forEach { xml ->
            assertFailsWith<PlistFormatException>("expected a failure for: $xml") {
                XmlPlist.decode(xml)
            }
        }
    }

    @Test
    fun nonZonedDateIsReadAsUtc() {
        assertEquals(
            PlistDate(1_700_000_000_000L),
            XmlPlist.decode("<plist><date>2023-11-14T22:13:20</date></plist>".toByteArray()),
        )
    }

    @Test
    fun thrownTypeIsTheSharedFormatException() {
        val e = assertFailsWith<PlistFormatException> { XmlPlist.decode("<plist><widget/></plist>".toByteArray()) }
        assertTrue(e.message!!.contains("widget"))
    }

    // --- writer ---

    @Test
    fun encodeDecodesBackThroughEveryElementType() {
        val value: Map<String, Any?> = mapOf(
            "string" to "light phone",
            "integer" to 42L,
            "int" to 7,
            "real" to 1.5,
            "true" to true,
            "false" to false,
            "data" to byteArrayOf(1, 2, 3, 4),
            "date" to PlistDate(1_700_000_000_000L),
            "list" to listOf("a", 7L, listOf("inner")),
            "nested" to mapOf("inner" to "deep"),
        )
        val decoded = XmlPlist.decode(XmlPlist.encode(value)) as Map<*, *>
        assertEquals(value["string"], decoded["string"])
        assertEquals(42L, decoded["integer"])
        assertEquals(7L, decoded["int"])
        assertEquals(1.5, decoded["real"])
        assertEquals(true, decoded["true"])
        assertEquals(false, decoded["false"])
        assertContentEquals(byteArrayOf(1, 2, 3, 4), decoded["data"] as ByteArray)
        assertEquals(PlistDate(1_700_000_000_000L), decoded["date"])
        assertEquals(value["list"], decoded["list"])
        assertEquals(mapOf("inner" to "deep"), decoded["nested"])
    }

    @Test
    fun encodeMatchesTheHandWrittenShape() {
        val expected = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
                <dict>
                    <key>a</key>
                    <integer>1</integer>
                </dict>
            </plist>
        """.trimIndent()
        assertEquals(expected, XmlPlist.encode(mapOf("a" to 1L)).toString(Charsets.UTF_8).trimEnd())
    }

    @Test
    fun encodeEscapesSpecialCharacters() {
        val decoded = XmlPlist.decode(XmlPlist.encode(mapOf("k" to "<&\"'>"))) as Map<*, *>
        assertEquals("<&\"'>", decoded["k"])
    }

    @Test
    fun encodeRejectsUnrepresentableValues() {
        assertFailsWith<PlistFormatException> { XmlPlist.encode(mapOf("a" to BpUid(1uL))) }
        assertFailsWith<PlistFormatException> { XmlPlist.encode(mapOf<String, Any?>("a" to null)) }
    }

    @Test
    fun decodeProtocolParsesTheBareProtocolDocument() {
        val document = "<Protocol><plist version=\"1.0\"><dict><key>a</key><integer>1</integer></dict></plist></Protocol>"
        assertEquals(mapOf("a" to 1L), XmlPlist.decodeProtocol(document.toByteArray()))
    }

    @Test
    fun decodeProtocolExtractsTheSpanFromALargerResponseDocument() {
        // rev 26 (live 2026-10-02): the activation answered <Document><Protocol>…</Protocol>
        // <ScrollView>… — the surrounding UI XML is not well-formed enough for the parser, so
        // the Protocol span is extracted and parsed alone.
        val wrapped = """
            <?xml version="1.0" encoding="UTF-8"?>
            <Document>
                <Protocol><plist version="1.0"><dict><key>device-activation</key><dict/></dict></plist></Protocol>
                <ScrollView xmlns="http://www.apple.com/ui" broken="&amp; &lt;unclosed>
            </Document>
        """.trimIndent()
        assertEquals(
            mapOf("device-activation" to emptyMap<String, Any?>()),
            XmlPlist.decodeProtocol(wrapped.toByteArray()),
        )
    }
}
