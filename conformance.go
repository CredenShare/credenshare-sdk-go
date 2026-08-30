package credenshare

// The normative wire-specification vectors, and a self-check that runs this SDK against them.
//
//	go run github.com/CredenShare/credenshare-sdk-go/cmd/credenshare-conformance@latest
//
// The vectors are embedded with go:embed rather than read from disk, so they travel with the
// binary and cannot go missing in a container that shipped only the executable.
//
// This lives in the root package on purpose. A separate package would have to reach the
// fixed-salt and fixed-IV parameters the vectors require, which would mean exporting them —
// and an exported "use this IV" knob is one autocomplete away from somebody reusing an IV in
// production, which destroys AES-GCM's guarantees outright. Keeping the checks here keeps
// those parameters unexported.
//
// That the fixture is normative matters more here than in most libraries. The application and
// the four SDKs share no code by design — a package the production application depended on
// would mean a compromised publish is a compromised application — so nothing but these vectors
// holds the five implementations together. Drift between them does not surface as a test
// failure in normal use. It surfaces as content that can never be decrypted.

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"reflect"
)

//go:embed vectors.v1.json
var vectorsJSON []byte

// SupportedVectorsVersion is the fixture version this code was written against. A silent bump
// would mean every check asserts against a contract nobody wrote it for, which is worse than
// failing.
const SupportedVectorsVersion = 1

// ConformanceVectorsJSON returns the embedded fixture bytes, so a caller can hash them.
func ConformanceVectorsJSON() []byte { return vectorsJSON }

type vectors struct {
	Version int `json:"version"`
	HKDF    []struct {
		Name   string `json:"name"`
		IKM    string `json:"ikm"`
		Salt   string `json:"salt"`
		Info   string `json:"info"`
		Length int    `json:"length"`
		Out    string `json:"out"`
	} `json:"hkdf"`
	Fragment struct {
		Key     string `json:"key"`
		Encoded string `json:"encoded"`
		Rejects []struct {
			Input  string `json:"input"`
			Reason string `json:"reason"`
		} `json:"rejects"`
	} `json:"fragment"`
	AccessToken struct {
		Key   string `json:"key"`
		Token string `json:"token"`
	} `json:"access_token"`
	PasscodeVerifier []struct {
		Passcode string `json:"passcode"`
		Verifier string `json:"verifier"`
	} `json:"passcode_verifier"`
	Content []struct {
		Name      string `json:"name"`
		Key       string `json:"key"`
		Salt      string `json:"salt"`
		IV        string `json:"iv"`
		Passcode  string `json:"passcode"`
		Plaintext string `json:"plaintext"`
		Blob      string `json:"blob"`
	} `json:"content"`
	SeedKeypair []struct {
		Name            string `json:"name"`
		Seed            string `json:"seed"`
		Scalar          string `json:"scalar"`
		PublicKey       string `json:"public_key"`
		PublicKeyB64URL string `json:"public_key_b64url"`
	} `json:"seed_keypair"`
	CustodyKeypair struct {
		CustodySecret   string `json:"custody_secret"`
		Seed            string `json:"seed"`
		PublicKey       string `json:"public_key"`
		PublicKeyB64URL string `json:"public_key_b64url"`
	} `json:"custody_keypair"`
	ECDHWrap struct {
		WrapVersion        int    `json:"wrap_version"`
		RecipientSeed      string `json:"recipient_seed"`
		RecipientPublicKey string `json:"recipient_public_key"`
		EphemeralSeed      string `json:"ephemeral_seed"`
		Salt               string `json:"salt"`
		IV                 string `json:"iv"`
		Payload            string `json:"payload"`
		Wrapped            string `json:"wrapped"`
	} `json:"ecdh_wrap"`
}

func loadVectors() (*vectors, error) {
	var parsed vectors
	if err := json.Unmarshal(vectorsJSON, &parsed); err != nil {
		return nil, fmt.Errorf("parsing the embedded fixture: %w", err)
	}
	if parsed.Version != SupportedVectorsVersion {
		return nil, fmt.Errorf(
			"the embedded fixture is version %d, but this SDK implements version %d",
			parsed.Version, SupportedVectorsVersion,
		)
	}
	return &parsed, nil
}

// A ConformanceCheck is one named vector. Run returns nil on success.
type ConformanceCheck struct {
	Name string
	Run  func() error
}

func unhex(text string) []byte {
	raw, _ := hex.DecodeString(text)
	return raw
}

func expectEqual(what string, got, want any) error {
	if !reflect.DeepEqual(got, want) {
		return fmt.Errorf("%s\n  expected: %v\n  actual:   %v", what, want, got)
	}
	return nil
}

// ConformanceChecks returns every vector as an individually named check.
//
// Returned as a slice rather than run, so a caller — the CLI, or `go test` — can report them
// one by one instead of stopping at the first, which matters when a derivation change breaks a
// whole section at once.
func ConformanceChecks() ([]ConformanceCheck, error) {
	v, err := loadVectors()
	if err != nil {
		return nil, err
	}

	var checks []ConformanceCheck

	for _, c := range v.HKDF {
		c := c
		checks = append(checks, ConformanceCheck{"hkdf/" + c.Name, func() error {
			out, err := hkdfDerive(unhex(c.IKM), unhex(c.Salt), c.Info, c.Length)
			if err != nil {
				return err
			}
			return expectEqual("HKDF output", hex.EncodeToString(out), c.Out)
		}})
	}

	checks = append(checks, ConformanceCheck{"fragment/encode", func() error {
		got, err := EncodeFragment(unhex(v.Fragment.Key))
		if err != nil {
			return err
		}
		return expectEqual("encoded fragment", got, v.Fragment.Encoded)
	}})

	checks = append(checks, ConformanceCheck{"fragment/decode", func() error {
		got, err := DecodeFragment(v.Fragment.Encoded)
		if err != nil {
			return err
		}
		return expectEqual("decoded content key", hex.EncodeToString(got), v.Fragment.Key)
	}})

	for i, reject := range v.Fragment.Rejects {
		i, reject := i, reject
		// Refusals are part of the contract, not extra credit: a client that accepts a
		// truncated fragment produces a key that decrypts nothing, and reports it as a content
		// error somewhere far away from the mangled link that caused it.
		wanted := ErrMalformedKey
		if reject.Reason == "missing-key" {
			wanted = ErrMissingKey
		}
		checks = append(checks, ConformanceCheck{
			fmt.Sprintf("fragment/rejects/%d/%s", i, reject.Reason),
			func() error {
				_, err := DecodeFragment(reject.Input)
				if err == nil {
					return fmt.Errorf("%q was accepted; the fixture requires a refusal", reject.Input)
				}
				if !errors.Is(err, wanted) {
					// The distinction is not pedantry. "Your link is incomplete" and "this
					// link is damaged" have different remedies, and both look identical on
					// screen.
					return fmt.Errorf("expected %v for %q, got %v", wanted, reject.Input, err)
				}
				return nil
			},
		})
	}

	checks = append(checks, ConformanceCheck{"access_token", func() error {
		got, err := AccessToken(unhex(v.AccessToken.Key))
		if err != nil {
			return err
		}
		return expectEqual("access token", got, v.AccessToken.Token)
	}})

	for i, c := range v.PasscodeVerifier {
		i, c := i, c
		// Numbered rather than named after the passcode: one of these cases is deliberately
		// non-ASCII, and a legacy console code page would turn printing its name into a crash
		// in the tool meant to be diagnosing crashes.
		checks = append(checks, ConformanceCheck{fmt.Sprintf("passcode_verifier/%d", i), func() error {
			got, err := PasscodeVerifier(c.Passcode)
			if err != nil {
				return err
			}
			return expectEqual("passcode verifier", got, c.Verifier)
		}})
	}

	for _, c := range v.Content {
		c := c
		var passcode *string
		if c.Passcode != "" {
			p := c.Passcode
			passcode = &p
		}

		checks = append(checks, ConformanceCheck{"content/" + c.Name + "/encrypt", func() error {
			var fields []Field
			if err := json.Unmarshal([]byte(c.Plaintext), &fields); err != nil {
				return err
			}
			opts := []EncryptOption{
				func(cfg *encryptConfig) { cfg.salt = unhex(c.Salt) },
				func(cfg *encryptConfig) { cfg.iv = unhex(c.IV) },
			}
			if passcode != nil {
				opts = append(opts, WithPasscode(*passcode))
			}
			blob, err := EncryptContent(unhex(c.Key), fields, opts...)
			if err != nil {
				return err
			}
			// Byte-identical, not merely decryptable. A blob that differs while still
			// decrypting here would hide a JSON-serialisation difference — key order,
			// separators, HTML escaping — that another implementation may not tolerate. Go's
			// default HTML escaping is exactly such a difference, and this is what catches it.
			return expectEqual("content blob", blob, c.Blob)
		}})

		checks = append(checks, ConformanceCheck{"content/" + c.Name + "/decrypt", func() error {
			// The decrypt direction is the one that proves interoperability: the blob in the
			// fixture was produced by a different implementation, so reading it means this
			// client can read what that one wrote.
			var want []Field
			if err := json.Unmarshal([]byte(c.Plaintext), &want); err != nil {
				return err
			}
			got, err := DecryptContent(unhex(c.Key), c.Blob, passcode)
			if err != nil {
				return err
			}
			return expectEqual("decrypted fields", got, want)
		}})
	}

	for _, c := range v.SeedKeypair {
		c := c
		checks = append(checks, ConformanceCheck{"seed_keypair/" + c.Name, func() error {
			pair, err := KeypairFromSeed(unhex(c.Seed))
			if err != nil {
				return err
			}
			// The scalar is checked as well as the public key. Both would have to be wrong
			// together for a bias in the reduction to slip through unnoticed.
			if err := expectEqual("scalar", padHex(pair.Scalar), c.Scalar); err != nil {
				return err
			}
			if err := expectEqual("public key", hex.EncodeToString(pair.PublicKeyRaw), c.PublicKey); err != nil {
				return err
			}
			return expectEqual("public key (base64url)", pair.PublicKeyB64URL, c.PublicKeyB64URL)
		}})
	}

	checks = append(checks, ConformanceCheck{"custody_keypair", func() error {
		pair, err := CustodyKeypair(v.CustodyKeypair.CustodySecret)
		if err != nil {
			return err
		}
		// The seed is checked too: it is the value a different implementation has to arrive at
		// independently, and a mismatch here explains a public-key mismatch below it.
		if err := expectEqual("custody seed", hex.EncodeToString(pair.Seed), v.CustodyKeypair.Seed); err != nil {
			return err
		}
		if err := expectEqual("custody public key", hex.EncodeToString(pair.PublicKeyRaw), v.CustodyKeypair.PublicKey); err != nil {
			return err
		}
		return expectEqual("custody public key (base64url)", pair.PublicKeyB64URL, v.CustodyKeypair.PublicKeyB64URL)
	}})

	w := v.ECDHWrap
	checks = append(checks, ConformanceCheck{"ecdh_wrap/wrap", func() error {
		wrapped, err := WrapToPublicKey(
			unhex(w.Payload), unhex(w.RecipientPublicKey),
			func(cfg *wrapConfig) { cfg.ephemeralSeed = unhex(w.EphemeralSeed) },
			func(cfg *wrapConfig) { cfg.salt = unhex(w.Salt) },
			func(cfg *wrapConfig) { cfg.iv = unhex(w.IV) },
		)
		if err != nil {
			return err
		}
		return expectEqual("wrapped blob", wrapped, w.Wrapped)
	}})

	checks = append(checks, ConformanceCheck{"ecdh_wrap/unwrap", func() error {
		payload, err := UnwrapWithSeed(w.Wrapped, unhex(w.RecipientSeed))
		if err != nil {
			return err
		}
		return expectEqual("unwrapped payload", hex.EncodeToString(payload), w.Payload)
	}})

	checks = append(checks, ConformanceCheck{"ecdh_wrap/roundtrip", func() error {
		recipient, err := KeypairFromSeed(unhex(w.RecipientSeed))
		if err != nil {
			return err
		}
		payload := unhex(w.Payload)
		wrapped, err := WrapToPublicKey(payload, recipient.PublicKeyRaw)
		if err != nil {
			return err
		}
		raw, err := b64.DecodeString(wrapped)
		if err != nil {
			return err
		}
		// 1 version + 65 public + 16 salt + 12 iv + payload + 16 tag. A 32-byte payload wraps
		// to exactly 142 bytes, which is a useful field check when something downstream
		// rejects a wrap without saying why.
		if err := expectEqual("wrap length", len(raw), 1+65+16+12+len(payload)+16); err != nil {
			return err
		}
		if err := expectEqual("version byte", int(raw[0]), w.WrapVersion); err != nil {
			return err
		}
		got, err := UnwrapWithSeed(wrapped, unhex(w.RecipientSeed))
		if err != nil {
			return err
		}
		return expectEqual("unwrapped payload", hex.EncodeToString(got), w.Payload)
	}})

	return checks, nil
}

func padHex(value *big.Int) string {
	raw := make([]byte, keyLen)
	value.FillBytes(raw)
	return hex.EncodeToString(raw)
}

// A ConformanceFailure is one check that did not pass.
type ConformanceFailure struct {
	Name   string
	Reason string
}

// RunConformance runs every check, collecting failures rather than stopping at the first.
func RunConformance(verbose bool, log func(string)) (int, []ConformanceFailure, error) {
	checks, err := ConformanceChecks()
	if err != nil {
		return 0, nil, err
	}

	passed := 0
	var failures []ConformanceFailure
	for _, check := range checks {
		if err := check.Run(); err != nil {
			failures = append(failures, ConformanceFailure{check.Name, err.Error()})
			if verbose {
				log("FAIL " + check.Name + "\n" + err.Error())
			}
			continue
		}
		passed++
		if verbose {
			log("ok   " + check.Name)
		}
	}
	return passed, failures, nil
}
