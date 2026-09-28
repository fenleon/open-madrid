package dev.fenn.imessage.registration

import dev.fenn.imessage.ids.IdsHttpResponse
import dev.fenn.imessage.ids.IdsHttp
import dev.fenn.imessage.ids.LookupTransport
import dev.fenn.imessage.ids.TunnelReply

// Port note: these two scripted doubles lived beside the :ids tests in the originating repo
// (one source tree, one package); module boundaries here split them out. They are verbatim
// copies of the :ids test doubles, retargeted at the same interfaces.

/**
 * Scripted [IdsHttp] test double: hands back [responses] in order and records every call.
 * One response per expected call — an unscripted extra call throws.
 */
class ScriptedIdsHttp(private val responses: List<IdsHttpResponse>) : IdsHttp {

    class Call(
        val method: String,
        val url: String,
        val headers: Map<String, String>,
        val body: ByteArray,
        val contentType: String,
    )

    val calls = mutableListOf<Call>()
    private var next = 0

    override suspend fun get(url: String, headers: Map<String, String>): IdsHttpResponse {
        calls.add(Call("GET", url, headers, ByteArray(0), ""))
        return responses[next++]
    }

    override suspend fun put(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        calls.add(Call("PUT", url, headers, body, contentType))
        return responses[next++]
    }

    override suspend fun post(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): IdsHttpResponse {
        calls.add(Call("POST", url, headers, body, contentType))
        return responses[next++]
    }
}

/** Scripted [LookupTransport] — the tunnel is faked, never the network. */
class ScriptedLookupTransport(replies: List<TunnelReply>) : LookupTransport {

    class Call(val url: String, val headers: Map<String, String>, val body: ByteArray, val contentType: String)

    val calls = mutableListOf<Call>()
    private val replies = replies.toList()
    private var next = 0

    override suspend fun exchange(
        url: String,
        headers: Map<String, String>,
        body: ByteArray,
        contentType: String,
    ): TunnelReply {
        calls.add(Call(url, headers, body, contentType))
        return replies[next++]
    }
}
