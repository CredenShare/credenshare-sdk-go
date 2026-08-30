# Changelog

## 0.1.0 — unreleased

First release.

- End-to-end encrypted share creation, listing and expiry against the `/v1` API. Encryption
  happens locally; the content key never reaches CredenShare.
- **No dependencies outside the standard library.** HKDF is forty lines of `crypto/hmac` rather
  than a module: a security SDK earning a dependency for that is a poor trade, and it is worth
  more to somebody auditing this than the forty lines cost.
- Split API credentials. The custody part never leaves the machine — the bearer value is
  assembled from parsed parts, with a second assertion at the request boundary, and both
  `String` and `GoString` withhold the secrets so `%v` cannot leak one into a log.
- Webhook signature verification, including the dual-signature rotation grace window and a
  symmetric replay-tolerance check. `Verify` returns only an `error`, never `(bool, error)` —
  the latter invites `ok, _ :=` and a receiver that accepts everything.
- `go run .../cmd/credenshare-conformance` verifies an installed copy against the wire
  specification's vectors, embedded with `go:embed`.
- `encoding/json` HTML escaping is turned off. It is on by default and no other implementation
  escapes, so a field containing `<`, `>` or `&` would otherwise produce a blob no other client
  could reproduce. The conformance vectors do not cover it; a dedicated test does.
