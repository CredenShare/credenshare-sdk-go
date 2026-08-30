package webhooks

// Webhook verification.
//
// Most of these assert refusals. A verifier that accepts too much is worse than none, because
// it produces a system that looks verified and is not.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

const (
	secret = "whsec_5NIQiWnzkbjIRSAX0ilnFLBOoIfnDMi16D3F5jrhSbo"
	other  = "whsec_someone-elses-secret-entirely-different-value"
)

var (
	body = []byte(`{"event":"share.created","short_code":"abc123"}`)
	now  = time.Unix(1_700_000_000, 0)
)

func mac(key string, payload []byte, at int64) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(fmt.Sprintf("%d.", at)))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func sign(key string, payload []byte, at int64) string {
	return fmt.Sprintf("t=%d,v1=%s", at, mac(key, payload, at))
}

func opts() *Options { return &Options{Now: now} }

func TestAGenuineDeliveryVerifies(t *testing.T) {
	if err := Verify(body, sign(secret, body, now.Unix()), []string{secret}, opts()); err != nil {
		t.Fatal(err)
	}
}

func TestForgeriesAreRefused(t *testing.T) {
	cases := map[string]func() error{
		"another secret": func() error {
			return Verify(body, sign(other, body, now.Unix()), []string{secret}, opts())
		},
		"a tampered body": func() error {
			return Verify(append(body, ' '), sign(secret, body, now.Unix()), []string{secret}, opts())
		},
		"re-serialised JSON": func() error {
			// The most common reason a correct implementation appears broken: re-serialising
			// parsed JSON changes the bytes, so the MAC no longer matches.
			var parsed map[string]any
			_ = json.Unmarshal(body, &parsed)
			reserialised, _ := json.MarshalIndent(parsed, "", "  ")
			return Verify(reserialised, sign(secret, body, now.Unix()), []string{secret}, opts())
		},
	}
	for name, run := range cases {
		if err := run(); !errors.Is(err, ErrVerification) {
			t.Errorf("%s: got %v, want ErrVerification", name, err)
		}
	}
}

func TestTheReplayWindow(t *testing.T) {
	// Without a timestamp check, anyone who captured one delivery could replay it forever.
	old := now.Unix() - int64(DefaultTolerance.Seconds()) - 60
	if err := Verify(body, sign(secret, body, old), []string{secret}, opts()); err == nil ||
		!strings.Contains(err.Error(), "outside the") {
		t.Errorf("an old delivery gave %v", err)
	}

	// A receiver's clock can be AHEAD as easily as behind. Rejecting only one direction fails
	// for half the machines that are wrong.
	future := now.Unix() + int64(DefaultTolerance.Seconds()) + 60
	if err := Verify(body, sign(secret, body, future), []string{secret}, opts()); err == nil ||
		!strings.Contains(err.Error(), "outside the") {
		t.Errorf("a future delivery gave %v", err)
	}

	inside := now.Unix() + int64(DefaultTolerance.Seconds()) - 10
	if err := Verify(body, sign(secret, body, inside), []string{secret}, opts()); err != nil {
		t.Errorf("a delivery inside the window gave %v", err)
	}
}

func TestTheTimestampCannotBeSwappedForAFreshOne(t *testing.T) {
	// It is inside the signed material, so moving it invalidates the MAC.
	stale := now.Unix() - 10_000
	header := sign(secret, body, stale)
	forward := strings.Replace(header, fmt.Sprintf("t=%d", stale), fmt.Sprintf("t=%d", now.Unix()), 1)
	if err := Verify(body, forward, []string{secret}, opts()); err == nil ||
		!strings.Contains(err.Error(), "no signature matched") {
		t.Fatalf("got %v", err)
	}
}

func TestTheRotationGraceWindow(t *testing.T) {
	// For 24 hours after a rotation, deliveries carry both signatures. That is what lets a
	// receiver roll its configuration without dropping anything — without it, the moment of
	// rotation IS an outage.
	dual := sign(secret, body, now.Unix()) + ",v1=" + mac(other, body, now.Unix())

	for _, secrets := range [][]string{{secret}, {other}, {other, secret}} {
		if err := Verify(body, dual, secrets, opts()); err != nil {
			t.Errorf("%v gave %v", secrets, err)
		}
	}

	// Two signatures widen WHO can verify, not WHAT verifies.
	if err := Verify(body, dual, []string{"whsec_a-third-secret"}, opts()); !errors.Is(err, ErrVerification) {
		t.Errorf("an unrelated secret gave %v", err)
	}
}

func TestMalformedHeadersAreRefusedWithAReason(t *testing.T) {
	zeros := strings.Repeat("0", 64)
	cases := map[string]string{
		"":                                    "missing",
		"   ":                                 "missing",
		"v1=" + zeros:                         "no timestamp",
		fmt.Sprintf("t=%d", now.Unix()):       "no v1 signature",
		"t=notanumber,v1=" + zeros:            "not a unix time",
		fmt.Sprintf("t=%d,v1=zz", now.Unix()): "no signature matched",
	}
	for header, want := range cases {
		err := Verify(body, header, []string{secret}, opts())
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("header %q gave %v, want one mentioning %q", header, err, want)
		}
	}
}

func TestNoSecretIsAnErrorNotAPass(t *testing.T) {
	for _, secrets := range [][]string{nil, {}, {""}, {"  "}} {
		err := Verify(body, sign(secret, body, now.Unix()), secrets, opts())
		if err == nil || !strings.Contains(err.Error(), "no signing secret") {
			t.Errorf("%v gave %v", secrets, err)
		}
	}
}

func TestNilOptionsUseTheDefaults(t *testing.T) {
	// The zero value has to work: a caller passing nil is the common case, and a nil
	// dereference in a verifier is a verifier that panics on every genuine delivery.
	if err := Verify(body, sign(secret, body, time.Now().Unix()), []string{secret}, nil); err != nil {
		t.Fatal(err)
	}
}
