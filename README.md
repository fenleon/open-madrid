# Open Madrid

**An open implementation of Apple's madrid protocol — better known as iMessage.**

"Madrid" is Apple's internal codename for iMessage. This repository is a clean-room, plain-old-
open-source implementation of the protocol in Kotlin: the binary and XML property-list codecs,
the APNs "courier" push client, the IDS identity service, the encryption envelope, and the full
registration/activation chain. It is not an app; it is the engine an app can be built on.

The name follows the [open-absinthe](https://github.com/JJTech0130/open-absinthe) lineage —
"open-" plus Apple's internal codename. Unlike open-absinthe, whose public repository contains a
mock placeholder and no actual functionality, **everything here is real, readable, and licensed**:
the validation and registration layers that other projects keep closed or ship as binary blobs
are implemented in the open, from protocol facts.

## Why another project?

Almost every existing route to iMessage is closed in some way:

| Project | What it is | The catch |
|---|---|---|
| rustpush | The maintained engine (Rust) | SSPL license — reading its code can contaminate yours |
| pypush | The original Python PoC | SSPL, and activation stopped working after Apple's Dec 2023 fix |
| imessagego | Go implementation | AGPL (the only ordinary open-source license in the space) |
| BlueBubbles | A working client | Needs a Mac running 24/7 to relay and decrypt |
| open-absinthe | The validation-data layer | Public repository, closed source — a mock, no functionality |
| OpenBubbles hosted | A hosted service | Someone else's server sees your messages |

**Open Madrid's aim:** a permissively licensed (Apache-2.0), dependency-light, fully readable
implementation of the protocol — the first one where the registration and validation layers are
open too. Facts about the protocol live in a spec ([docs/imessage-protocol-spec.md](docs/imessage-protocol-spec.md));
every fact cites its source. Code is written from the spec, never from the other projects.

## What is validated

- **The parsers handle real Apple bytes.** The actual 405-entry IDS bag and 65-entry APNs bag,
  captured from a registered device, are committed as test fixtures and decoded with exact-value
  assertions — 344 offline tests, all green.
- **Two live, unauthenticated probes against Apple succeeded:** both bag endpoints return valid
  plists this stack parses, and the certificate pinning validates Apple's real TLS chains. A
  recurring drift check ships with the repo (`:engine:runProbe`).
- **The courier's auth model is settled:** the TLS handshake succeeds, then the server demands
  the Albert client certificate (a TLS 1.3 post-handshake `certificate_required` alert) — the
  client-certificate wiring point is confirmed correct.
- **The registration chain runs end-to-end against scripted Apple responses** (a full dry-run
  test).
- **The protocol around it is proven live** by this project's private sibling implementation:
  a working device-identity chain (Apple's validation endpoint, key establishment, the 645-byte
  validation blob), SRP login with Apple's GSA endpoints, and the decrypted response parsing —
  on real accounts. Those findings are folded into the spec here.

## What is not validated (yet)

- **Nothing has registered a real device or sent a real message.** First live activation is the
  next milestone.
- The crypto envelopes have round-trip tests but no known-answer vectors captured from a live
  device.
- A few wire details remain capture-bound guesses, tracked in the spec's open-questions checklist.
- **PQ3** (Apple's newer post-quantum encryption) is unsupported — the same older fallback every
  third-party iMessage client uses today.

## Keeping the license clean (read this before contributing)

This is a **clean-room**: contributors never read the source of rustpush, pypush, imessagego, or
their forks. Two roles, kept strictly apart:

1. **Readers** study the existing projects. Their only output is the **spec** — plain-language
   protocol notes with cited sources. Facts can't be copyrighted; code can.
2. **Writers** work only from the spec, Apple's own documentation, and recordings of their own
   device's traffic. Don't open the other projects' source, don't read their diffs or issues when
   debugging, and don't paste their identifiers into commits or issues.

Why: it keeps this code fully ours — free of viral licenses, acceptable to F-Droid and other
distribution channels, and safe to embed anywhere.

## The Apple-material rule

No Apple-derived code or binary ships in this repository — not the IMDAppleServices framework,
not Apple's FairPlay identity. The bundled identity under
`registration/src/main/resources/imessage/fairplay/` is a **synthetic placeholder** (generated,
self-signed, for tests only). Live activation requires Apple's real FairPlay identity and
registration framework, which each user stages themselves — exactly like the Mac identity the
protocol requires anyway.

## Building

Standalone — no sibling checkouts required:

```bash
./gradlew build          # all modules + the full test suite
./gradlew :engine:runProbe   # the live drift check (unauthenticated bag/cert probes)
```

## License

[Apache-2.0](LICENSE).
