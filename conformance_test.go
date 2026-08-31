package credenshare

// The conformance suite. This is the only meaningful definition of correct.
//
// The vectors are normative. The application, this SDK and the three others share no code by
// design, so nothing but these vectors holds the five implementations together — and drift
// between them does not produce a test failure in normal use, it produces content that can
// never be decrypted.
//
// The derivation cases catch drift early. The decrypt and unwrap cases are the ones that
// actually prove interoperability, because passing them means this implementation can read what
// a *different* one wrote.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func TestConformanceVectors(t *testing.T) {
	checks, err := ConformanceChecks()
	if err != nil {
		t.Fatalf("loading the vectors: %v", err)
	}
	if len(checks) == 0 {
		// A suite that silently runs nothing passes just as loudly as one that runs
		// everything, which is the failure mode worth guarding against here.
		t.Fatal("no conformance checks were produced")
	}

	for _, check := range checks {
		check := check
		t.Run(check.Name, func(t *testing.T) {
			if err := check.Run(); err != nil {
				t.Error(err)
			}
		})
	}
}

// pinnedVectorsDigest is the SHA-256 of vectors.v1.json.
//
// Updating this by hand is a deliberate act. If a conformance test fails, the fix is almost
// never to re-pin this — it is to fix the implementation. Re-pin only when intentionally
// adopting a newly published fixture, in a commit that says so and nothing else.
const pinnedVectorsDigest = "91e70661be51edbc4522d202c533292d1eac92691d1fbb02e9eaa13eb23a582c"

func TestTheEmbeddedFixtureHasNotBeenEdited(t *testing.T) {
	// Nothing but the conformance vectors holds five independent implementations together. If
	// a vendored copy can be edited to make a failing test pass, that guarantee is gone: the
	// fixture stops being a contract and becomes a mirror of whatever this SDK happens to do.
	digest := sha256.Sum256(ConformanceVectorsJSON())
	if got := hex.EncodeToString(digest[:]); got != pinnedVectorsDigest {
		t.Fatalf(
			"vectors.v1.json does not match its pinned digest\n  expected: %s\n  actual:   %s\n"+
				"If a conformance test was failing, fix the implementation rather than the "+
				"fixture. If this fails only on Windows, check .gitattributes: the digest is "+
				"of the LF bytes.",
			pinnedVectorsDigest, got,
		)
	}
}

func TestTheEmbeddedFixtureMatchesThePublishedOne(t *testing.T) {
	url := os.Getenv("CREDENSHARE_VECTORS_URL")
	if url == "" {
		t.Skip("set CREDENSHARE_VECTORS_URL to check against the published fixture")
	}

	// Byte-for-byte, not semantically: a whitespace-only difference still means the two files
	// came from different generator runs, and that is worth knowing before it becomes a
	// difference that matters.
	response, err := http.Get(url)
	if err != nil {
		t.Fatalf("fetching the published fixture: %v", err)
	}
	defer response.Body.Close()
	// Check the status BEFORE comparing bytes. A 404 body also "differs from the embedded
	// fixture", and the message below would report that as drift and send a maintainer to
	// overwrite a known-good fixture with an HTML error page.
	if response.StatusCode != http.StatusOK {
		t.Fatalf(
			"the published fixture is not reachable: %s returned HTTP %d. Drift is NOT "+
				"being checked. Fix the URL - do not touch vectors.v1.json.",
			url, response.StatusCode,
		)
	}
	published, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading the published fixture: %v", err)
	}
	if !json.Valid(published) {
		t.Fatalf(
			"the published fixture at %s is not JSON. Drift is NOT being checked. Fix the "+
				"URL - do not touch vectors.v1.json.", url,
		)
	}
	if !bytes.Equal(published, ConformanceVectorsJSON()) {
		t.Fatal(
			"the embedded fixture differs from the published one. The spec has moved; " +
				"update vectors.v1.json and re-pin its digest.",
		)
	}
}

// -- properties of this implementation, not of the fixture ---------------------------

func TestAnEmptySaltIsNotABlockOfZeros(t *testing.T) {
	// RFC 5869 makes an empty salt and a 32-zero-byte salt equivalent for SHA-256 — both pad
	// to the same 64-byte HMAC block — but an implementation that padded to some other length
	// would silently produce different output, and the failure would appear as undecryptable
	// content rather than as a test failure.
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
	}
	empty, err := hkdfDerive(ikm, nil, "x", 32)
	if err != nil {
		t.Fatal(err)
	}
	zeros, err := hkdfDerive(ikm, make([]byte, 32), "x", 32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(empty, zeros) {
		t.Fatalf("empty salt %x != 32-zero salt %x", empty, zeros)
	}
}

func TestJSONHTMLEscapingIsOff(t *testing.T) {
	// THE Go-specific trap.
	//
	// encoding/json escapes <, > and & as \u003c, \u003e and \u0026 by
	// default. No other
	// implementation does, so a field containing any of them would produce a blob this client
	// can decrypt and no other client can reproduce - a difference invisible until two people
	// using different SDKs compare notes. The conformance vectors do not happen to contain one
	// of those characters, so this asserts it directly rather than relying on them.
	//
	// Decrypting the blob is not enough: an escaped blob decrypts here too, and json.Unmarshal
	// turns the escapes back into the original characters. The WIRE PLAINTEXT is what another
	// implementation has to reproduce, so the test opens the blob by hand to see those bytes.
	key := make([]byte, keyLen)
	fields := []Field{{Key: "Q & A <tag>", Value: "a > b && c < d", Type: "text"}}

	blob, err := EncryptContent(key, fields)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := b64.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := contentCipher(key, raw[:saltLen], nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := aead.Open(nil, raw[saltLen:saltLen+ivLen], raw[saltLen+ivLen:], nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, escape := range []string{`\u0026`, `\u003c`, `\u003e`} {
		if strings.Contains(string(plaintext), escape) {
			t.Fatalf("the wire plaintext is HTML-escaped (%s), which no other implementation produces: %s",
				escape, plaintext)
		}
	}
	if !strings.Contains(string(plaintext), "Q & A <tag>") {
		t.Fatalf("the wire plaintext lost the raw characters: %s", plaintext)
	}
	// And it still round-trips.
	decrypted, err := DecryptContent(key, blob, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted[0].Key != fields[0].Key || decrypted[0].Value != fields[0].Value {
		t.Fatalf("round trip changed the field: %+v", decrypted[0])
	}
}

func TestAMissingKeyIsDistinctFromADamagedOne(t *testing.T) {
	// Not pedantry: "your link is incomplete" and "this share expired" look identical on
	// screen and have opposite remedies.
	for _, fragment := range []string{"", "#"} {
		if _, err := DecodeFragment(fragment); !errors.Is(err, ErrMissingKey) {
			t.Errorf("DecodeFragment(%q) = %v, want ErrMissingKey", fragment, err)
		}
	}
	for _, fragment := range []string{"1AAAA", "9AAAA", "1!!!!"} {
		if _, err := DecodeFragment(fragment); !errors.Is(err, ErrMalformedKey) {
			t.Errorf("DecodeFragment(%q) = %v, want ErrMalformedKey", fragment, err)
		}
	}
}

func TestATruncatedBlobIsReportedAsTruncated(t *testing.T) {
	// Checked before anything else, so nobody goes looking for a wrong passcode.
	_, err := DecryptContent(make([]byte, keyLen), b64.EncodeToString([]byte("short")), nil)
	if !errors.Is(err, ErrWireFormat) || !strings.Contains(err.Error(), "smallest possible") {
		t.Fatalf("got %v, want a truncation error", err)
	}
}

func TestAWrongPasscodeAndAlteredContentAreIndistinguishable(t *testing.T) {
	// Telling them apart would hand an attacker an oracle.
	v, err := loadVectors()
	if err != nil {
		t.Fatal(err)
	}
	wrong := "not-hunter2"
	if _, err := DecryptContent(unhex(v.Content[1].Key), v.Content[1].Blob, &wrong); !errors.Is(err, ErrWireFormat) {
		t.Errorf("a wrong passcode gave %v", err)
	}
	altered := v.Content[0].Blob[:len(v.Content[0].Blob)-4] + "AAAA"
	if _, err := DecryptContent(unhex(v.Content[0].Key), altered, nil); !errors.Is(err, ErrWireFormat) {
		t.Errorf("altered content gave %v", err)
	}
}

func TestTheIVIsNeverReusedUnderTheSameKey(t *testing.T) {
	// The one mistake that destroys AES-GCM outright. Cheap to assert, catastrophic to miss.
	key, err := NewContentKey()
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i := 0; i < 24; i++ {
		blob, err := EncryptContent(key, []Field{{Key: "k", Value: string(rune('a' + i)), Type: "text"}})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := b64.DecodeString(blob)
		if err != nil {
			t.Fatal(err)
		}
		iv := hex.EncodeToString(raw[saltLen : saltLen+ivLen])
		if seen[iv] {
			t.Fatalf("the IV %s was reused under the same key", iv)
		}
		seen[iv] = true
	}
}

func TestValidateFieldsRefusesAnEmptyKey(t *testing.T) {
	// The Go type system stops the `label:` spelling that catches the dynamic languages, but a
	// caller unmarshalling from JSON with the wrong member name lands here instead: Key is
	// empty, and a field with a blank label renders blank with no error anywhere.
	err := ValidateFields([]Field{{Value: "v", Type: "password"}})
	if err == nil || !strings.Contains(err.Error(), "visible label") {
		t.Fatalf("got %v, want a refusal naming the visible label", err)
	}
}

func TestARecipientPublicKeyMustBeAnUncompressedPoint(t *testing.T) {
	for _, key := range [][]byte{make([]byte, pubKeyLen), make([]byte, 64)} {
		if _, err := WrapToPublicKey(make([]byte, keyLen), key); err == nil {
			t.Errorf("a %d-byte key starting with 0x%02x was accepted", len(key), key[0])
		}
	}
}

func TestUnwrappingWithTheWrongSeedFails(t *testing.T) {
	v, err := loadVectors()
	if err != nil {
		t.Fatal(err)
	}
	wrong := bytes.Repeat([]byte{9}, keyLen)
	if _, err := UnwrapWithSeed(v.ECDHWrap.Wrapped, wrong); !errors.Is(err, ErrWireFormat) {
		t.Fatalf("got %v, want ErrWireFormat", err)
	}
}
