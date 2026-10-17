# Open Madrid

An open implementation of Apple's madrid protocol (iMessage) in Kotlin: the binary plist codecs, the APNs "courier" push client, the IDS identity service, the encryption envelopes, the registration/activation chain, and the ADI anisette chain (device provisioning, OTP headers, the validation-stamp mint).

## Status

Verified against Apple:

- **Registration** — the full §1.1→§1.4 chain (validation-data mint → authenticate → register) succeeds with the library's own stamp (2026-10-17, exercised end-to-end on-device)
- **Bags and TLS**
- **ADI/anisette chain** 
- **The validation endpoints**

Not yet (as of 17.10.2026):

- No message send or receive over the courier; renewal idempotence untested.
- Crypto envelopes have round-trip tests but no known-answer vectors from a live device.
- A few wire details are capture-bound guesses, tracked in the spec's open-questions checklist.
- PQ3 unsupported.

The 2026-10-17 milestone: the last stamp gap is closed. The EstablishKeyResponse keys
under `establish_key(S-BOX(draw))` where the draw is the 16 client bytes riding the
request blob's field32 plaintext (`plain32[5:21]`) — established by hardware-watchpoint
proof against the reference client and confirmed by a live register with our own mint.

## Why another project?

Almost every route to iMessage is closed in some way:

| Project | License / catch |
|---|---|
| rustpush | SSPL |
| pypush | SSPL |
| imessagego | AGPL |
| BlueBubbles | Needs a Mac running 24/7 |
| OpenBubbles | Depends on closed-source open-absinthe* |

*[open-absinthe](https://github.com/JJTech0130/open-absinthe), the reference everyone else depends on, is a mock placeholder with no real code; this is the real thing.

The protocol facts behind the code are written up in the spec: [docs/imessage-protocol-spec.md](docs/imessage-protocol-spec.md).

## Contributing

This is a clean-room. Contributors never read the source of rustpush, pypush, imessagego, or their forks. Two roles, kept apart:

1. Readers study the existing projects. Their only output is the spec.
2. Writers work only from the spec, Apple's documentation, and recordings of their own device's traffic.

This keeps the code fully open and acceptable to F-Droid and other distribution channels.

## Apple material

No Apple-derived code or binary ships here, including the IMDAppleServices framework. The bundled identity in `registration/src/main/resources/imessage/fairplay/` is a synthetic placeholder, generated and self-signed, for tests only; live activation requires each user to stage Apple's real FairPlay identity themselves.

One documented exception: the ClearADI and pear lookup tables (constant data the ADI ciphers need) were reconstructed by analyzing a compiled ADI implementation and ship as generated Kotlin source, decoded at startup. No Apple code, binary, or resource file is committed. The extraction method is in the spec.

## Using it

Tagged releases build on [JitPack](https://jitpack.io/#fenleon/open-madrid) — module coordinates and code snippets for the mint, anisette, and the engine are in [docs/USAGE.md](docs/USAGE.md).

## Building

```bash
./gradlew build             # all modules + tests
./gradlew :engine:runProbe  # live drift check
```

## License

[Apache-2.0](LICENSE).

Support my work on [Ko-fi](https://ko-fi.com/fenleon) or [GitHub Sponsors](https://github.com/sponsors/fenleon).
