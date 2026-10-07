package dev.fenn.imessage.registration

/**
 * Static .rodata tables of the ClearADI white-box (librust_lib_bluebubbles), embedded as
 * base64 source in [ClearAdiTablesData] (no Apple-derived binary ships in the repo) and
 * decoded once at first use. vaddr V maps to offset V - [TABLES_BASE] in the tables image;
 * consts likewise with [CONSTS_BASE]. Word tables are stored little-endian (the x86 memory
 * image).
 */
internal object ClearAdiTables {
    private const val TABLES_BASE = 0x24DCC0
    private const val CONSTS_BASE = 0x1A0800

    private val tablesBin: ByteArray by lazy { decode(ClearAdiTablesData.tablesChunks) }
    private val constsBin: ByteArray by lazy { decode(ClearAdiTablesData.constsChunks) }
    private val wordTableCache = HashMap<Int, IntArray>()

    private fun decode(chunks: List<String>): ByteArray =
        java.util.Base64.getMimeDecoder().decode(chunks.joinToString(""))

    /** 256-entry u32 table at .rodata [vaddr], read little-endian. */
    fun wordTable(vaddr: Int): IntArray = wordTableCache.getOrPut(vaddr) {
        val off = vaddr - TABLES_BASE
        IntArray(256) { i ->
            val p = off + 4 * i
            (tablesBin[p].toInt() and 0xff) or
                ((tablesBin[p + 1].toInt() and 0xff) shl 8) or
                ((tablesBin[p + 2].toInt() and 0xff) shl 16) or
                ((tablesBin[p + 3].toInt() and 0xff) shl 24)
        }
    }

    /** n-entry u32 table (the gensource mixtables are 64 entries). */
    fun wordTable(vaddr: Int, count: Int): IntArray {
        val off = vaddr - TABLES_BASE
        return IntArray(count) { i ->
            val p = off + 4 * i
            (tablesBin[p].toInt() and 0xff) or
                ((tablesBin[p + 1].toInt() and 0xff) shl 8) or
                ((tablesBin[p + 2].toInt() and 0xff) shl 16) or
                ((tablesBin[p + 3].toInt() and 0xff) shl 24)
        }
    }

    /** 256-byte table at .rodata [vaddr]. */
    fun byteTable(vaddr: Int): ByteArray {
        val off = vaddr - TABLES_BASE
        return tablesBin.copyOfRange(off, off + 256)
    }

    /** 16-byte constant block from consts.bin. */
    fun consts16(vaddr: Int): ByteArray {
        val off = vaddr - CONSTS_BASE
        return constsBin.copyOfRange(off, off + 16)
    }

    /** The 0xC00 qword-index blob at the start of tables.bin (.rodata 0x24dcc0). */
    fun blob(): ByteArray = tablesBin.copyOfRange(0, 0xC00)

    /** n raw bytes at .rodata [vaddr] (tables.bin image). */
    fun raw(vaddr: Int, n: Int): ByteArray {
        val off = vaddr - TABLES_BASE
        return tablesBin.copyOfRange(off, off + n)
    }

    /** The 0x600 qword-index blob at .rodata 0x2682c0 (gen_otp_ios VM program). */
    fun vmBlob(): ByteArray = raw(0x2682c0, 0x600)
}
