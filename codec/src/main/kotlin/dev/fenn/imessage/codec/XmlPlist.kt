package dev.fenn.imessage.codec

import java.io.ByteArrayInputStream
import java.time.Instant
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.Base64
import javax.xml.parsers.DocumentBuilder
import javax.xml.parsers.DocumentBuilderFactory
import org.w3c.dom.Element
import org.xml.sax.ErrorHandler
import org.xml.sax.InputSource
import org.xml.sax.SAXParseException

/**
 * XML plist reader.
 *
 * The bag responses and their embedded payloads are XML plists (§1.2 [CAP-BAGCT]), as are the
 * register/authenticate/activation bodies and responses (§1.4, §1.2). [Plist.parse] picks
 * between this codec and the binary codec ([Bplist]) by content.
 *
 * Elements map to the same Kotlin values as the binary codec's native bridge:
 * `dict` → LinkedHashMap<String, Any?>, `array` → List<Any?>, `string`/`key` → String,
 * `integer` → Long, `real` → Double, `true`/`false` → Boolean, `data` → ByteArray
 * (base64), `date` → [PlistDate].
 */
object XmlPlist {

    fun decode(bytes: ByteArray): Any? {
        val document = try {
            builder().parse(ByteArrayInputStream(bytes))
        } catch (e: SAXParseException) {
            throw PlistFormatException("malformed XML plist at line ${e.lineNumber}: ${e.message}")
        } catch (e: Exception) {
            throw PlistFormatException("malformed XML plist: ${e.message}")
        }
        val root = document.documentElement ?: throw PlistFormatException("empty XML document")
        if (root.tagName != "plist") throw PlistFormatException("<${root.tagName}> is not a <plist>")
        val values = elementChildren(root)
        if (values.size != 1) {
            throw PlistFormatException("<plist> holds ${values.size} value elements, expected exactly 1")
        }
        return value(values[0])
    }

    /**
     * A parser that never resolves an external entity or an external DTD: it parses
     * untrusted network input, so an entity reference must not become a fetch. The
     * DOCTYPE itself stays tolerated (Apple's XML plists carry the property-list DTD
     * declaration) and is simply inert — every external reference is refused below.
     */
    private fun builder(): DocumentBuilder {
        val factory = DocumentBuilderFactory.newInstance()
        factory.isNamespaceAware = false
        factory.setExpandEntityReferences(false)
        feature(factory, "http://xml.org/sax/features/external-general-entities", false)
        feature(factory, "http://xml.org/sax/features/external-parameter-entities", false)
        feature(factory, "http://apache.org/xml/features/nonvalidating/load-external-dtd", false)
        try {
            factory.isXIncludeAware = false
        } catch (e: UnsupportedOperationException) {
            // parser has no XInclude support — nothing to turn off
        }
        val builder = factory.newDocumentBuilder()
        builder.setEntityResolver { _, _ -> InputSource(java.io.StringReader("")) }
        builder.setErrorHandler(object : ErrorHandler {
            override fun warning(e: SAXParseException) {}
            override fun error(e: SAXParseException) = throw e
            override fun fatalError(e: SAXParseException) = throw e
        })
        return builder
    }

    /** Best-effort: parsers differ in which of these features they know. */
    private fun feature(factory: DocumentBuilderFactory, name: String, value: Boolean) {
        try {
            factory.setFeature(name, value)
        } catch (e: Exception) {
            // feature not supported by this parser — the entity resolver still guards the fetch
        }
    }

    private fun value(e: Element): Any? = when (e.tagName) {
        "dict" -> dict(e)
        "array" -> elementChildren(e).map { value(it) }
        "string" -> e.textContent
        "integer" -> e.textContent.trim().toLongOrNull()
            ?: throw PlistFormatException("<integer> is not an integer: '${e.textContent.trim()}'")
        "real" -> e.textContent.trim().toDoubleOrNull()
            ?: throw PlistFormatException("<real> is not a number: '${e.textContent.trim()}'")
        "true" -> true
        "false" -> false
        "data" -> data(e)
        "date" -> date(e.textContent)
        "key" -> throw PlistFormatException("<key> outside a <dict>")
        else -> throw PlistFormatException("unknown plist element <${e.tagName}>")
    }

    private fun dict(e: Element): Map<String, Any?> {
        val children = elementChildren(e)
        if (children.size % 2 != 0) {
            throw PlistFormatException("<dict> holds ${children.size} elements — key/value pairs expected")
        }
        val out = LinkedHashMap<String, Any?>(children.size / 2)
        var i = 0
        while (i < children.size) {
            val key = children[i]
            if (key.tagName != "key") {
                throw PlistFormatException("<${key.tagName}> where <key> expected in <dict>")
            }
            out[key.textContent] = value(children[i + 1])
            i += 2
        }
        return out
    }

    /** `<data>` content is base64; Apple's writer wraps long payloads with newlines and tabs. */
    private fun data(e: Element): ByteArray {
        val text = e.textContent.filterNot { it.isWhitespace() }
        return try {
            Base64.getDecoder().decode(text)
        } catch (e: IllegalArgumentException) {
            throw PlistFormatException("<data> is not valid base64: ${e.message}")
        }
    }

    /** Apple writes `<date>` as an ISO-8601 instant (`2024-01-02T03:04:05Z`). */
    private fun date(text: String): PlistDate {
        val trimmed = text.trim()
        val instant = try {
            OffsetDateTime.parse(trimmed).toInstant()
        } catch (e: DateTimeParseException) {
            try {
                Instant.parse(trimmed)
            } catch (e2: DateTimeParseException) {
                try {
                    LocalDateTime.parse(trimmed).toInstant(ZoneOffset.UTC)
                } catch (e3: DateTimeParseException) {
                    throw PlistFormatException("<date> is not an ISO-8601 instant: '$trimmed'")
                }
            }
        }
        return PlistDate(instant.toEpochMilli())
    }

    /**
     * The Albert activation response (§1.2): an XML document whose outer `<Protocol>` block
     * wraps a plist document. Parses the plist inside the Protocol element.
     *
     * Apple sometimes wraps the `<Protocol>` inside a larger response document (rev 26,
     * live 2026-10-02: the activation answered `<Document><Protocol>…</Protocol><ScrollView>…`,
     * whose surrounding UI XML is not well-formed enough for the parser) — the Protocol block
     * is extracted by span first and parsed alone; a bare `<Protocol>` document parses as before.
     */
    fun decodeProtocol(bytes: ByteArray): Any? {
        val text = PROTOCOL_SPAN.find(String(bytes, Charsets.UTF_8))?.value
            ?: String(bytes, Charsets.UTF_8)
        val document = try {
            builder().parse(ByteArrayInputStream(text.toByteArray(Charsets.UTF_8)))
        } catch (e: SAXParseException) {
            throw PlistFormatException("malformed XML at line ${e.lineNumber}: ${e.message}")
        } catch (e: Exception) {
            throw PlistFormatException("malformed XML: ${e.message}")
        }
        val root = document.documentElement ?: throw PlistFormatException("empty XML document")
        if (root.tagName != "Protocol") throw PlistFormatException("<${root.tagName}> is not a <Protocol>")
        val plists = elementChildren(root)
        if (plists.size != 1 || plists[0].tagName != "plist") {
            throw PlistFormatException("<Protocol> must hold exactly one <plist>")
        }
        val values = elementChildren(plists[0])
        if (values.size != 1) {
            throw PlistFormatException("<plist> holds ${values.size} value elements, expected exactly 1")
        }
        return value(values[0])
    }

    /**
     * XML plist writer — the mirror of [decode]'s type mapping (spec §1.4: the register body
     * is serialized as an XML plist). UID has no XML-plist representation and `null` has none
     * at all; both throw rather than emit something the other side cannot read.
     */
    fun encode(value: Any?): ByteArray {
        val out = StringBuilder(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" " +
                "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n" +
                "<plist version=\"1.0\">\n",
        )
        write(value, out, 1)
        out.append("</plist>\n")
        return out.toString().toByteArray(Charsets.UTF_8)
    }

    private fun write(value: Any?, out: StringBuilder, depth: Int) {
        val pad = "    ".repeat(depth)
        when (value) {
            is Map<*, *> -> {
                out.append(pad).append("<dict>\n")
                for ((key, v) in value) {
                    out.append(pad).append("    <key>").append(escape(key as? String
                        ?: throw PlistFormatException("dict key is not a string: $key")))
                        .append("</key>\n")
                    write(v, out, depth + 1)
                }
                out.append(pad).append("</dict>\n")
            }
            is List<*> -> {
                out.append(pad).append("<array>\n")
                for (v in value) write(v, out, depth + 1)
                out.append(pad).append("</array>\n")
            }
            is String -> out.append(pad).append("<string>").append(escape(value)).append("</string>\n")
            is Long -> out.append(pad).append("<integer>").append(value).append("</integer>\n")
            is Int -> out.append(pad).append("<integer>").append(value).append("</integer>\n")
            is Double -> out.append(pad).append("<real>").append(value).append("</real>\n")
            is Boolean -> out.append(pad).append(if (value) "<true/>\n" else "<false/>\n")
            is ByteArray -> out.append(pad).append("<data>")
                .append(Base64.getEncoder().encodeToString(value)).append("</data>\n")
            is PlistDate -> out.append(pad).append("<date>").append(value.toIso8601()).append("</date>\n")
            is BpUid, null ->
                throw PlistFormatException("XML plist cannot represent $value")
            else -> throw PlistFormatException("no XML plist representation for ${value::class.java}")
        }
    }

    private fun escape(text: String): String = buildString(text.length) {
        for (c in text) when (c) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&apos;")
            else -> append(c)
        }
    }

    /** Element children only — text, comments and processing instructions are ignored. */
    private fun elementChildren(e: Element): List<Element> {
        val children = e.childNodes
        val out = ArrayList<Element>()
        for (i in 0 until children.length) {
            val node = children.item(i)
            if (node is Element) out.add(node)
        }
        return out
    }

    /** The §1.2 activation response's `<Protocol>` span, extracted from larger documents (rev 26). */
    private val PROTOCOL_SPAN = Regex("<Protocol>.*</Protocol>", RegexOption.DOT_MATCHES_ALL)
}
