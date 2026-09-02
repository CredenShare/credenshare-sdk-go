# Changelog

## 0.2.0 — 2026-09-02

The secure-request surface: a keyless collect link, the sealed submissions to it, and the
32-byte seed that is the only thing able to read them. Plus `GetStats`.

Additive — nothing on the already-published shares surface changed shape or behaviour — so
this is a minor bump. The names below were settled ACROSS the four SDKs before any of them
published this surface, because a name in a Go module's import path cannot be renamed after a
tag exists.

### Added

- **`CreateRequest`, `ListRequests`, `IterateRequests`, `GetRequest`, `DeleteRequest`,
  `ListSubmissions`, `IterateSubmissions`** and the types they carry: `SecureRequest`,
  `RequestSummary`, `RequestPage`, `RequestDeletion`, `RequestField`, `Submission`,
  `SubmissionPage`, `CreateRequestParams`.
- **`GetStats`**, with `Stats`, `ShareCounts` and `DailyView`. The counts are nested —
  `stats.Shares.Active` — matching the API, the specification and the sibling SDKs.
- **`DecryptSubmission(data, seed)`** and **`Submission.Decrypt(seed)`**. The blob comes
  first and the key second, the same order as the other three SDKs.
- **`CollectLinkFor(shortCode)`** and **`AccessLinkFor(shortCode, seed)`** on the client, plus
  `SecureRequest.CollectLink` and `SecureRequest.AccessLink`. Neither link is derivable from
  an API response: the `/r/` segment and the origin belong to the application, and the access
  fragment is version-prefixed, which is the part a hand-assembled link gets wrong.
- **`SeedLength`** (32), so a caller validating a stored seed does not have to write the
  literal.
- **`Client.Do` and `Call`**, the escape hatch for an endpoint this SDK does not wrap, with the
  same authentication, retries, error mapping and custody-secret boundary check as every typed
  method. A `POST`, `PUT` or `PATCH` made through it is given an `Idempotency-Key` when
  `Call.Headers` does not carry one — those three and **not** every non-GET. A `GET` and a
  `DELETE` are given none: neither endpoint reads the header, a repeated delete is idempotent
  by construction, and `ExpireShare`'s `DELETE /shares/{code}` has published those bytes since
  0.1.4, so adding an inert header to them would be a wire change this release has no reason
  to make. A key the CALLER supplies is forwarded on any method, `DELETE` included, exactly as
  written.
- **`ErrRequestSeedTransmitted`**, raised by a boundary assertion in `CreateRequest`: the
  serialized body AND the outgoing `Idempotency-Key` are scanned for the seed as unpadded
  base64url, as standard base64 and as hex, and a match refuses the call rather than sending
  it. The header is covered because it is caller-supplied and leaves the machine — a
  deterministic key derived from a deterministic seed would otherwise carry the seed out past
  a check that only read the body.
- A wrong-length `CreateRequestParams.Seed` is now `ErrMalformedKey`, raised before the
  keypair is derived, rather than whatever the crypto primitive underneath returns.

### Security

- **`SecureRequest` withholds its seed and its access link from every reflexive
  serialization path**, not only from `fmt`. `MarshalJSON` and `slog.LogValue` are new here
  and both were leaks in the working tree: `json.Marshal` rendered the seed as base64 in full,
  and a `slog` JSON handler wrote it into the log line, because neither consults `String`. All
  four accessors — `String`, `GoString`, `MarshalJSON`, `LogValue` — take **value receivers**,
  so a dereferenced or copied value redacts too; a pointer receiver would have left
  `fmt.Sprintf("%+v", *created)` printing the seed while the same verb on the pointer looked
  clean. The collect link is deliberately kept: it is not a secret.
- **`CreateRequestParams` withholds its seed and its passcode from the same four paths**, on
  value receivers for the same reason. This is the wider window of the two: the seed is in the
  params BEFORE the call that returns it, so `fmt.Sprintf("%+v", params)` printed the 32 bytes,
  `%#v` printed them as `[]uint8{...}`, `json.Marshal` emitted `"Seed":"<base64>"` and an
  `slog` JSON handler wrote the same into the line — all of it upstream of a `SecureRequest`
  that redacts perfectly. The passcode goes with it: it is transmitted, but it is a value the
  caller chose and may have reused elsewhere. `MarshalJSON` here is deliberately lossy and is
  NOT the create body — that body is assembled member by member inside `CreateRequest`, which
  a test now asserts.
- **`SeedKeypair` withholds its seed, its scalar and its private key** from `String`,
  `GoString`, `MarshalJSON` and `slog.LogValue`, again on value receivers, since
  `KeypairFromSeed` returns a pointer and it is the dereferenced value that a pointer receiver
  would have missed. Three of its five members are the private key in different clothes, and
  one of them made a plain `%v` dangerous on its own: `Scalar` is a `*big.Int`, which is a
  `Stringer`, so the private scalar printed in decimal with no verbose verb involved. The
  public half is kept in every rendering, because a redaction that removes the identity is not
  usable by whoever is reading the log.

### Fixed, before 0.2.0 was published

None of these ever shipped, so nothing in the wild breaks. They are recorded because the
repository is public and somebody may have pinned to a commit from the window before the tag.

- **Submissions are no longer paged.** The deployed endpoint reads neither `page` nor `limit`
  and answers with every client-encrypted row plus a `count`, so `ListSubmissions` takes only
  a short code and `IterateSubmissions` makes exactly one HTTP call. Paging it would have
  re-requested and re-yielded the same rows.
- `SubmissionPage` exposes the API's own `Count` as its own member rather than folding it into
  a `Total` that a pagination block never sent.
- `Submission` no longer carries an `ExpiredAt`. The endpoint sends `short_code`,
  `created_at`, `data` and `encryption_type`; a member that is always nil reads as a broken
  field rather than as an absent one. (The specification documents the field and is wrong.)
- `DeleteRequest` returns `*RequestDeletion` rather than a bare outcome string, and an outcome
  the API did not send stays empty rather than being reported as `"expired"`.
- The request-field validator is unexported. The share-side `ValidateFields` stays public;
  a request's prompts are checked on the one path that sends them.
- **`SecureRequest.PublicKey` is the API's echo**, with the locally derived key as the
  fallback, matching Node and Rust. It was set from the local derivation unconditionally,
  which made the member's own documented use — quoting it against `GetRequest`'s copy — a
  comparison of a local value with itself. A blank echo counts as no echo and takes the
  fallback, so the member is still never empty on a successful create.
- **`SubmissionPage.Count` is no longer backfilled from `len(Submissions)`.** Node, Python and
  Rust all leave it absent when the server omits it, precisely so that a count disagreeing
  with the number of rows is visible; the fallback made the two agree by construction and
  erased the one signal the member exists to carry. Go has no absent `int`, so an omitted
  count now reads as zero.
- **`RequestPage.HasMore` climbs the same three rungs as the other three SDKs** —
  `TotalPages`, then `Total`, then "a full page probably has a successor" — instead of
  answering only from `TotalPages`. One rung reports "no more" on a FULL page whenever the
  server omits the pagination block, which is how a walk returns a fraction of an account and
  says nothing. The two lower rungs are guarded on `Limit > 0`: a server echoing `"limit": 0`
  is believed, and `0 < Total` is true on every page including empty ones, which would convert
  the truncation into an unbounded run of requests — the failure Node hit and fixed.
  `SharePage.HasMore` is deliberately left alone: it shipped at 0.1.4, so its behaviour is not
  this release's to change, and `IterateShares` already carries the equivalent fallback inside
  the walk itself.

### Documentation

- The secure-requests section of the README states the two-encoding trap, the seed-redaction
  guarantee and what the boundary assertion actually covers.
- The README's redaction paragraph now covers `CreateRequestParams` and `SeedKeypair` as well
  as `SecureRequest`, and names the `*big.Int` `Stringer` that made a plain `%v` dangerous.
- "Idempotency and retries" says POST/PUT/PATCH rather than "every non-GET", and states why a
  `GET` and a `DELETE` are given nothing.
- The `PublicKey` echo and the un-backfilled `Count` are both stated where the surface is
  described, because both are members whose value a caller is meant to compare against
  something else.
- The conformance one-liner names `v0.2.0`.


## 0.1.4 — released 2026-08-30

The first version whose install instructions are the registry ones, because 0.1.3 is on the
registries. Also fixes a version string that had drifted.

### Fixed

- **The in-code version constant was stale.** It read `0.1.0` while `0.1.3` was published: the
  release guard compared the TAG to the manifest and never to this second copy. Go was already correct - its `Version` constant IS what the release guard checks.

### Documentation

- The install line is the registry command rather than a git URL.


## 0.1.3 — released 2026-08-30

No code change from 0.1.2. Cut to exercise the publish path with no stored credential: the npm
`NPM_TOKEN` bootstrap secret is deleted and publication now runs on OIDC trusted publishing, so
nothing long-lived exists in any repository that could publish this package.


## 0.1.2 — released 2026-08-30

The first version published to a package registry. No code change from 0.1.1: the conformance
fixture is byte-identical and every client still reports 24/24. Cut so that the published
version's own release workflow carries the npm OIDC version floor, which is what allows npm
publishing to move off a token immediately afterwards.


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
