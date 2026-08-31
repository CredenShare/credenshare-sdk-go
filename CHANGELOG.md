# Changelog

## 0.1.1 — released 2026-08-30

`v0.1.0` was tagged before the release-facing files were corrected, so the artifact resolved at
that tag told consumers to install unpinned and its changelog denied its own release. This
version contains those corrections. Nothing about the cryptography or the wire format changed
between the two; the conformance fixture is byte-identical.

### Fixed

- A comment in `crypto_extra_test.go` named a test that does not exist. The test meant is
  `TestJSONHTMLEscapingIsOff`.

### Documentation

- The conformance one-liner in the README names the tag rather than `@latest`, and the
  changelog no longer describes 0.1.0 as unreleased or argues from there being no tags — text
  that shipped inside the tag, with the GitHub Release notes pointing readers at it.

## 0.1.0 — released 2026-08-30

First release.

### Breaking, before v0.1.0

These landed before `v0.1.0` was tagged, so no released version ever had the old shape and
nothing in the wild breaks. They are recorded because the repository is public and someone may
have pinned to a commit from the window before the tag existed — and because each was the right
fix for a real defect, which is worth stating alongside the break:

- **`Field` is no longer comparable.** It gained an `Extra map[string]json.RawMessage` member
  so that unknown members survive a decrypt/re-encrypt round trip; a struct containing a map
  cannot be compared, so `f1 == f2` no longer compiles and `Field` can no longer be a map key.
  Use **`Field.Equal(other)`**, added for exactly this, and key maps on `Field.Key`. The
  alternative was to keep deleting a newer sender's members silently, which is worse than a
  compile error that names itself.
- **`Options.MaxRetries` is now `*int`.** A plain `int` could not distinguish "zero retries"
  from "unset", so a caller who deliberately disabled retries was given the default of two.
  Use **`Retries(0)`**.
- **`webhooks.Options.Tolerance` is now `*time.Duration`.** Same reason: a zero Duration meant
  "use the five-minute default", so a test pinning the clock proved nothing. Use
  **`NoTolerance()`** or **`ToleranceOf(d)`**.

### Added

- `Options.Timeout`, with `DefaultTimeout` (30s). Previously the 30-second client was baked
  into `New` and a supplied `*http.Client` with no timeout of its own would wait forever.
- `CreateParams.Custody`, `.ItemKeyWrap` and `.OrganizationID`. `CustodyPublicKey` existed to
  register a custody key and nothing could use it, so every API-created share was custody
  `"none"` — the link was the only way back to the content. `Credential.WrapToCustody` computes
  the wrap inside the credential, so the custody secret still never leaves it.
- `Field.Extra`, preserving members this version does not know about.
- Sentinels for the refusals that previously matched none: `ErrAPI` (the catch-all, and it now
  genuinely matches **every** `*APIError` rather than the four whose kind happened to be it),
  `ErrInvalidField`, `ErrNotSupported`, `ErrDeliveryUnknown`.

### Fixed

- **A transport failure no longer claims nothing was created.** It returned
  `ErrServiceUnavailable`, documented as "nothing was created" — but Go's `Do` returns once
  headers arrive, so the request may well have been written and processed. It is
  `ErrDeliveryUnknown` now. A caller believing the old claim would retry a create with a fresh
  idempotency key and mint a second copy of the same secret.
- **`IterateShares` no longer trusts the server's echoed page number** for its termination
  condition, so a server echoing a constant can no longer make it stop after page one or loop
  forever. It also keeps paging while pages come back full when `TotalPages` is absent.
- **`errors.Is` matches something for every refusal.** A 400, a 500, or a 409 without code 105
  previously set no sentinel at all, so the documented pattern fell through silently on the two
  statuses a caller hits most.
- `ValidateFields` and `ReadLink` return errors that wrap sentinels rather than bare values.
- The drift test checks the HTTP status before comparing bytes. A 404 was reported as fixture
  drift, with advice to overwrite a known-good fixture with the error page.

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
- `encoding/json` HTML escaping is turned off, in `EncryptContent` AND in `Field.MarshalJSON`.
  It is on by default and no other implementation escapes, so a field containing `<`, `>` or
  `&` would otherwise produce a blob no other client could reproduce. The inner call is the
  load-bearing one: compaction never UNESCAPES, so an escape written by the marshaller would
  survive the outer setting untouched. The conformance vectors now cover these characters, and
  a dedicated test asserts on the marshaller's bytes as well.
