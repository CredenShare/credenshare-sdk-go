package credenshare

import (
	"encoding/json"
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
	// encoder - is asserted by TestHtmlEscapableCharactersSurviveUnescaped in
	// conformance_test.go, which opens the blob by hand. Not duplicated here.
}
