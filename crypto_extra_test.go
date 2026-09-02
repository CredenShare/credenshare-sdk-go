package credenshare

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// A newer sender adds a member. An older reader must not delete it.
//
// The struct used to be closed, so decoding dropped anything unrecognised and re-encrypting
// wrote the field back without it. Nothing errored; the member was simply gone.
func TestUnknownMembersSurviveARoundTrip(t *testing.T) {
	const wire = `[{"key":"k","value":"v","type":"text","masked":true,"order":3}]`

	var fields []Field
	if err := json.Unmarshal([]byte(wire), &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 {
		t.Fatalf("got %d fields", len(fields))
	}
	if fields[0].Key != "k" || fields[0].Value != "v" || fields[0].Type != "text" {
		t.Fatalf("known members lost: %+v", fields[0])
	}
	if len(fields[0].Extra) != 2 {
		t.Fatalf("unknown members lost: %+v", fields[0].Extra)
	}

	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"masked":true`, `"order":3`} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("re-serialising dropped %s: %s", want, out)
		}
	}
}

// The three known members lead, in declaration order, whatever else is present.
func TestKnownMembersKeepDeclarationOrder(t *testing.T) {
	field := Field{
		Key:   "k",
		Value: "v",
		Type:  "text",
		Extra: map[string]json.RawMessage{"aaa": json.RawMessage(`1`)},
	}
	out, err := json.Marshal(field)
	if err != nil {
		t.Fatal(err)
	}
	// "aaa" sorts before every known member, so a naive map-based encoder would emit it first.
	if want := `{"key":"k","value":"v","type":"text","aaa":1}`; string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}

// A field with no unknown members must serialise exactly as it did before Extra existed,
// or every conformance vector changes.
func TestAFieldWithNoExtrasIsUnchanged(t *testing.T) {
	out, err := json.Marshal(Field{Key: "Password", Value: "s3cr3t", Type: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"key":"Password","value":"s3cr3t","type":"password"}`; string(out) != want {
		t.Fatalf("got %s, want %s", out, want)
	}
}

// Field's own marshaller must not escape, because the outer encoder cannot undo it.
//
// The first version of this test round-tripped through EncryptContent/DecryptContent and
// asserted the Key came back intact. That assertion is blind to the thing it is named for:
// json.Unmarshal turns < back into <, so it passed identically with escaping ON. The
// bytes MarshalJSON produces are what another implementation has to reproduce, so assert on
// those.
func TestFieldMarshallingDoesNotEscapeHTML(t *testing.T) {
	field := Field{Key: "a<b>c&d", Value: "a > b && c < d", Type: "text"}

	encoded, err := field.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	got := string(encoded)

	for _, escaped := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if strings.Contains(got, escaped) {
			t.Fatalf("MarshalJSON escaped HTML (%s): %s", escaped, got)
		}
	}
	for _, raw := range []string{"a<b>c&d", "a > b && c < d"} {
		if !strings.Contains(got, raw) {
			t.Fatalf("MarshalJSON did not emit %q verbatim: %s", raw, got)
		}
	}

	// The wire-plaintext half of this - that the same bytes survive EncryptContent's outer
	// encoder - is asserted by TestJSONHTMLEscapingIsOff in
	// conformance_test.go, which opens the blob by hand. Not duplicated here.
}

// Compile-time, so a receiver changed from a value to a pointer fails the build rather than
// one assertion inside one test. KeypairFromSeed returns a POINTER, so it is the value's
// method set — the one a dereference or a copy uses — that has to carry all four.
var (
	_ fmt.Stringer   = SeedKeypair{}
	_ fmt.GoStringer = SeedKeypair{}
	_ json.Marshaler = SeedKeypair{}
	_ slog.LogValuer = SeedKeypair{}
)

func TestASeedKeypairWithholdsItsPrivateHalvesFromEverySerializationPath(t *testing.T) {
	// Three of the five members are the private key in different clothes, and this struct is
	// worse than most: Scalar is a *big.Int, which is a Stringer, so a plain %v printed the
	// private scalar in decimal without anybody asking for a verbose verb. json.Marshal
	// rendered Seed as base64 and an slog JSON handler wrote the same into the log line.
	//
	// Pointer AND dereference AND copy: KeypairFromSeed hands back a pointer, so a pointer
	// receiver would have redacted the one form a caller does not usually print.
	seed := []byte("0123456789abcdef0123456789abcdef")
	keypair, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	copied := *keypair

	var logged strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("derived a keypair", "keypair", keypair)
	logger.Info("derived a keypair", "keypair", copied)

	asJSON, err := json.Marshal(keypair)
	if err != nil {
		t.Fatal(err)
	}
	asJSONValue, err := json.Marshal(copied)
	if err != nil {
		t.Fatal(err)
	}
	inASlice, err := json.Marshal([]SeedKeypair{copied})
	if err != nil {
		t.Fatal(err)
	}

	renderings := map[string]string{
		"%v on the pointer":        fmt.Sprintf("%v", keypair),
		"%v on a copy":             fmt.Sprintf("%v", copied),
		"%+v on the pointer":       fmt.Sprintf("%+v", keypair),
		"%+v on a copy":            fmt.Sprintf("%+v", copied),
		"%+v on a dereference":     fmt.Sprintf("%+v", *keypair),
		"%#v on the pointer":       fmt.Sprintf("%#v", keypair),
		"%#v on a copy":            fmt.Sprintf("%#v", copied),
		"%s on the pointer":        fmt.Sprintf("%s", keypair),
		"%s on a copy":             fmt.Sprintf("%s", copied),
		"a slice of them":          fmt.Sprintf("%v", []SeedKeypair{copied}),
		"json.Marshal(pointer)":    string(asJSON),
		"json.Marshal(copy)":       string(asJSONValue),
		"json.Marshal(slice)":      string(inASlice),
		"slog with a JSON handler": logged.String(),
	}

	scalarBytes := keypair.PrivateKey.Bytes()
	spellings := map[string]string{
		"the seed as raw bytes":     string(seed),
		"the seed as decimal bytes": fmt.Sprintf("%d", seed),
		"the seed as hex":           hex.EncodeToString(seed),
		"the seed as base64":        base64.StdEncoding.EncodeToString(seed),
		"the seed as base64url":     base64.RawURLEncoding.EncodeToString(seed),
		"the scalar in decimal":     keypair.Scalar.String(),
		"the scalar in hex":         keypair.Scalar.Text(16),
		"the private key as bytes":  string(scalarBytes),
		"the private key as hex":    hex.EncodeToString(scalarBytes),
		"the private key as base64": base64.StdEncoding.EncodeToString(scalarBytes),
	}

	for path, rendered := range renderings {
		for encoding, spelling := range spellings {
			if strings.Contains(rendered, spelling) {
				t.Errorf("%s leaked %s: %q", path, encoding, rendered)
			}
		}
		// The public half is not a secret, and a redaction that hides it leaves nothing
		// usable: which keypair was logged is the whole reason for logging one.
		if !strings.Contains(rendered, keypair.PublicKeyB64URL) {
			t.Errorf("%s dropped the public key: %q", path, rendered)
		}
	}
}
