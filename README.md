# CredenShare for Go

End-to-end encrypted secret sharing. **Encryption happens on your machine** — the content key
never reaches CredenShare, which is what makes "we cannot read your data" a property of the
system rather than a promise.

```bash
go get github.com/CredenShare/credenshare-sdk-go@v0.1.0
```

```go
package main

import (
    "context"
    "fmt"
    "os"

    credenshare "github.com/CredenShare/credenshare-sdk-go"
)

func main() {
    client, err := credenshare.New(os.Getenv("CREDENSHARE_KEY"), nil)
    if err != nil {
        panic(err)
    }

    share, err := client.CreateShare(context.Background(), credenshare.CreateParams{
        Title: "Staging deploy credentials",
        Fields: []credenshare.Field{
            {Key: "Username", Value: "deploy-bot", Type: "text"},
            {Key: "Password", Value: "correct horse", Type: "password"},
        },
    })
    if err != nil {
        panic(err)
    }

    fmt.Println(share.Link)
    // https://crs.sh/aB3dEf12#1xK9...
}
```

**That link is the secret.** The key lives in its fragment, which browsers never transmit.
Anyone holding the link can read the content; we cannot, and cannot recover it for you.

## No dependencies

Standard library only. HKDF is forty lines of `crypto/hmac` rather than a module — a security
SDK earning a dependency for that is a poor trade, and one fewer thing in your supply chain is
worth more to whoever audits this than the forty lines cost.

---

## The field object

`Field.Key` is the **visible label**, not an identifier. Go's types stop the `label:` spelling
that catches the dynamic clients, but a caller unmarshalling from JSON with the wrong member
name lands in the same place: `Key` empty, every field rendered blank, nothing erroring
anywhere. `ValidateFields` refuses that before anything is sent.

`Type` is one of `text`, `password`, `date`, `multiline`, `markdown`, `source_code`, and
decides how the recipient sees it: `password` is masked behind a reveal, `source_code` is
highlighted, `markdown` is rendered.

## A passcode

```go
share, err := client.CreateShare(ctx, credenshare.CreateParams{
    Title:    "Production database",
    Fields:   []credenshare.Field{{Key: "Password", Value: "s3cr3t", Type: "password"}},
    Passcode: "hunter2",
})
```

The passcode is mixed into the key derivation and never sent. The server receives only a
one-way verifier, so it can check an attempt without gaining the ability to decrypt. Share the
link and the passcode over different channels — that is the point of having both.

## Listing and expiring

```go
page, err := client.ListShares(ctx, 50, 1)
fmt.Println(page.Total, page.HasMore())

err = client.IterateShares(ctx, 100, func(s credenshare.ShareSummary) error {
    fmt.Println(s.ShortCode, s.ExpiredAt)
    return nil
})

err = client.ExpireShare(ctx, "aB3dEf12")
```

`ListShares` and `GetShare` return **metadata only** — never content, never a key. A short code
belonging to another account reports exactly as one that does not exist, so a credential cannot
be used to discover what other accounts hold.

`ExpireShare` **removes** the share rather than flagging it: a later `GetShare` returns
`ErrNotFound` rather than a row with an expiry set. Worth knowing if you reconcile against your
own records — a share you expired and one that never existed look identical afterwards.

There is deliberately **no method to read a share over the API**. The recipient path is
protected by proof-of-work and captcha gates that bearer auth skips, so exposing it to a
credential would be an enumeration bypass. Open the link in a browser.

## Idempotency and retries

Every create carries an `Idempotency-Key`. It exists so a **network** retry cannot leave a
second copy of a credential in the world, with its own link and audit trail, that you do not
know about. This client performs those retries itself, repeating the byte-identical request.

Setting your own `IdempotencyKey` does **not** make a second `CreateShare` a no-op, and no
field makes it one: encryption is randomised per call — a fresh salt and IV every time, which
AES-GCM requires — so the body differs and the API refuses with `ErrIdempotencyConflict`. That
is the header working, not failing.

Only network failures are retried. A 5xx is surfaced, because it may have committed and this
client cannot tell.

---

## Verifying webhooks

```go
import "github.com/CredenShare/credenshare-sdk-go/webhooks"

func handler(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(r.Body)   // the RAW bytes, before any decoding
    if err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }

    if err := webhooks.Verify(body, r.Header.Get(webhooks.SignatureHeader),
        []string{os.Getenv("WEBHOOK_SECRET")}, nil); err != nil {
        w.WriteHeader(http.StatusBadRequest)
        return
    }
    // ...
}
```

Two things people get wrong, both of which this package tries to make hard:

**Verify the raw body.** Read it with `io.ReadAll` and verify those bytes. Re-serialising
decoded JSON changes them — key order, spacing, escapes — and the signature will not match. It
is the most common reason a correct integration appears broken.

**Pass both secrets while rotating.** For 24 hours after you rotate, deliveries carry both
signatures so you can roll your configuration without dropping anything:

```go
webhooks.Verify(body, header, []string{newSecret, oldSecret}, nil)
```

`Verify` returns only an `error`. A `(bool, error)` signature invites `ok, _ := Verify(...)`,
and a receiver that ignores the error accepts everything while looking like it checks.

---

## API credentials

```
crs_sk_live_<keyId>.<authSecret>.<custodySecret>
                                  └ never transmitted
```

The third part is optional and, when present, **stays on your machine**. It is a separate
secret precisely so the server cannot reconstruct your custody private key: the auth secret
goes over the wire on every request, so deriving custody from it would mean the server *could*
decrypt. Not that it would — that it could, which is what zero-knowledge removes.

The bearer value is assembled from the parsed parts rather than by trimming the string, so a
third part cannot survive a formatting mistake and reach the wire, and there is a second
assertion at the request boundary. `Credential` implements both `String` and `GoString`, so
neither `%v` nor `%#v` can spill a secret into a log.

```go
key, err := client.Credential.CustodyPublicKey()  // register this; only the public half leaves
```

---

## The wire specification

This SDK implements the CredenShare wire and crypto specification, which ships in this
repository as [`CRYPTO_WIRE_SPEC.md`](CRYPTO_WIRE_SPEC.md). **The specification is
normative — not this code**, and not any other implementation. Where they disagree, this
is the bug.

Versioning, and how a release is cut, is in [`VERSIONING.md`](VERSIONING.md). Worth reading
before the first one: this SDK is not on a registry yet, and the release path needs
per-repository settings that do not exist yet.


The application and the four SDKs share no code, deliberately: a package the production
application depended on would mean a compromised publish is a compromised application. The cost
is drift, and drift here does not produce a test failure — it produces content that can never
be decrypted.

The vectors are embedded with `go:embed`, so they travel with the binary and cannot go missing
in a container that shipped only the executable:

```bash
go run github.com/CredenShare/credenshare-sdk-go/cmd/credenshare-conformance@latest -v
```

Non-zero exit on failure, so it works as a deployment gate. The vectors include cases that
**decrypt and unwrap material produced by a different implementation** — passing them means
this client can read what another one wrote, which is interoperability rather than
self-consistency.

### One Go-specific trap, handled

`encoding/json` escapes `<`, `>` and `&` as `\u003c`, `\u003e` and `\u0026` by default. No
other implementation escapes, so a field containing any of them would produce a blob this
client can decrypt and no other client can reproduce. This SDK turns the escaping off in both
places it matters: `EncryptContent`, and `Field`'s own marshaller.

The inner one is the load-bearing call, and not for the reason you might expect.
`encoding/json`'s compact pass never *unescapes*, so an escape written by `Field.MarshalJSON`
survives `EncryptContent`'s `SetEscapeHTML(false)` untouched — the outer setting cannot undo an
inner escape. (Calling the package-level `json.Marshal` on a `Field` directly does still
escape, since that compacts with escaping on. It does not affect the wire format, which only
ever goes through `EncryptContent`.)

The conformance fixture now carries a case containing all three characters, so this is caught
by the vectors rather than by folklore. A dedicated test asserts it as well, because the trap
is silent: the blob decrypts perfectly here and nowhere else.

## Errors

Branch with `errors.Is`; reach the status and request id with `errors.As` to `*APIError`.

| Sentinel | Means | What helps |
| -------- | ----- | ---------- |
| `ErrMissingKey` | a link arrived with no key | ask for the link again — something stripped it |
| `ErrMalformedKey` | the key is present but unusable | the link is truncated; ask for it again |
| `ErrWireFormat` | wrong passcode, or altered content | check the passcode. The two are indistinguishable by design |
| `ErrAuthentication` | credential unknown or revoked | mint a new one |
| `ErrPermission` | missing scope, or a plan without API access | check scopes, or upgrade |
| `ErrQuotaExceeded` | the plan's share allowance is spent | waiting does not help — expire old shares or change plan |
| `ErrIdempotencyConflict` | a key was replayed with a different body | expected on a caller-level replay; see above |
| `ErrRateLimited` | too many requests | wait `APIError.RetryAfter` seconds |
| `ErrServiceUnavailable` | a real HTTP 503; entitlements could not be resolved | nothing was created; retry |
| `ErrDeliveryUnknown` | delivered, but no response was read | it may have committed. Repeat the identical request — a fresh key here is how one secret becomes two |
| `ErrNotFound` | no such share, or not yours | a code from another account reads exactly like one that never existed |
| `ErrInvalidField` | a field is not `{Key, Value, Type}` | `Key` is the visible label — not "label", "name" or "title" |
| `ErrNotSupported` | the operation is deliberately absent | `ReadLink` — open the link in a browser instead |
| `ErrAPI` | any other refusal | the fallback, so `errors.Is(err, ErrAPI)` matches every `APIError` |

## Licence

Apache-2.0. Open source is a requirement here, not a preference: if the client performing the
encryption is closed, the claim that we cannot read your data is unverifiable.
