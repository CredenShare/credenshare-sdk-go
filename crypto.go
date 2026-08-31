// Package credenshare implements client-side cryptography and the /v1 API client for
// CredenShare — end-to-end encrypted secret sharing.
//
// Encryption happens on your machine. The content key never reaches CredenShare, which is
// what makes "we cannot read your data" a property of the system rather than a promise.
//
// This package implements the published wire specification. The specification is normative —
// not this code, and not any other implementation. Where they disagree, the specification is
// right and this is a bug.
//
// # Why this is written from the spec rather than ported
//
// The application, this SDK and the three others are independent implementations that share
// no code. That is a supply-chain decision: a package the production application depended on
// would mean a compromised publish is a compromised application. The cost is drift, and drift
// here does not produce a test failure — it produces content that can never be decrypted. The
// conformance vectors are what hold the implementations together, and they include cases that
// decrypt material produced by a *different* implementation. Passing them is the only
// meaningful definition of correct.
package credenshare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// FieldTypes are the types the recipient view knows how to render (section 2.2.1).
var FieldTypes = []string{"text", "password", "date", "multiline", "markdown", "source_code"}

// A Field is one labelled value in a share.
//
// Key is the VISIBLE LABEL. It is not "label", "name" or "title" — those are silently ignored
// by the recipient view, which renders the field with a blank label and no error anywhere.
type Field struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Type  string `json:"type"`

	// Extra holds members this version does not know about, so that a field written by a
	// newer sender survives being read and written again here.
	//
	// Without it the struct is closed: decoding drops anything unrecognised, and re-encrypting
	// writes the field back with those members gone. Nothing errors, and the loss is invisible
	// until whoever added the member wonders where it went.
	//
	// json.RawMessage rather than any, so the original bytes are preserved exactly instead of
	// being round-tripped through float64 and reformatted.
	Extra map[string]json.RawMessage `json:"-"`
}

// marshalNoEscapeHTML encodes v with HTML escaping off.
//
// The package-level json.Marshal escapes <, > and & even inside MarshalJSON output, which is
// the divergence EncryptContent turns off for the outer document. Field's own marshaller has
// to do the same or a field containing those characters is re-escaped on the way out.
func marshalNoEscapeHTML(v any) ([]byte, error) {
	var b strings.Builder
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// MarshalJSON writes key, value and type in that order, then any unknown members.
//
// Declaration order is the wire form, so it cannot be left to encoding/json's struct ordering
// by accident — and unknown members are written after the three known ones, sorted, so the
// output is deterministic for a given field.
func (f Field) MarshalJSON() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte('{')

	known := []struct {
		name  string
		value string
	}{{"key", f.Key}, {"value", f.Value}, {"type", f.Type}}
	for i, member := range known {
		if i > 0 {
			out.WriteByte(',')
		}
		name, err := marshalNoEscapeHTML(member.name)
		if err != nil {
			return nil, err
		}
		value, err := marshalNoEscapeHTML(member.value)
		if err != nil {
			return nil, err
		}
		out.Write(name)
		out.WriteByte(':')
		out.Write(value)
	}

	names := make([]string, 0, len(f.Extra))
	for name := range f.Extra {
		switch name {
		case "key", "value", "type":
			// A known member cannot also be an unknown one; the struct field wins.
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		encoded, err := marshalNoEscapeHTML(name)
		if err != nil {
			return nil, err
		}
		out.WriteByte(',')
		out.Write(encoded)
		out.WriteByte(':')
		out.Write(f.Extra[name])
	}

	out.WriteByte('}')
	return out.Bytes(), nil
}

// UnmarshalJSON keeps every member, known or not.
func (f *Field) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*f = Field{}
	for name, value := range raw {
		switch name {
		case "key":
			if err := json.Unmarshal(value, &f.Key); err != nil {
				return fmt.Errorf("field member 'key': %w", err)
			}
		case "value":
			if err := json.Unmarshal(value, &f.Value); err != nil {
				return fmt.Errorf("field member 'value': %w", err)
			}
		case "type":
			if err := json.Unmarshal(value, &f.Type); err != nil {
				return fmt.Errorf("field member 'type': %w", err)
			}
		default:
			if f.Extra == nil {
				f.Extra = make(map[string]json.RawMessage, len(raw))
			}
			kept := make(json.RawMessage, len(value))
			copy(kept, value)
			f.Extra[name] = kept
		}
	}
	return nil
}

// Lengths are exact, per section 0. Named rather than inlined so a truncated blob is rejected
// by arithmetic that reads like the specification.
const (
	saltLen     = 16
	ivLen       = 12
	tagLen      = 16
	keyLen      = 32
	pubKeyLen   = 65 // 0x04 || X(32) || Y(32)
	wrapVersion = 1
)

// hkdfDerive is HKDF-SHA-256 (RFC 5869), with info encoded as UTF-8.
//
// Implemented here rather than pulled from golang.org/x/crypto, which now requires a Go
// version far newer than this module targets — and a security SDK earning a dependency for
// forty lines of HMAC is a poor trade. This package has NO dependencies outside the standard
// library, which is worth more to somebody auditing it than the forty lines cost.
//
// An empty salt is passed through as a zero-length byte slice rather than being replaced with
// a block of zeros. RFC 5869 makes those equivalent for HMAC-SHA-256 — a zero-length HMAC key
// and a 32-zero-byte one both pad to the same 64-byte block — but the specification calls it
// out because an implementation that pads to some *other* length silently produces different
// output and fails conformance.
func hkdfDerive(ikm, salt []byte, info string, length int) ([]byte, error) {
	if length < 0 || length > 255*sha256.Size {
		return nil, fmt.Errorf("hkdf: cannot derive %d bytes", length)
	}

	// Extract.
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(ikm)
	prk := extractor.Sum(nil)

	// Expand. T(0) is empty; T(n) = HMAC(prk, T(n-1) || info || n).
	out := make([]byte, 0, length)
	var previous []byte
	for counter := byte(1); len(out) < length; counter++ {
		expander := hmac.New(sha256.New, prk)
		expander.Write(previous)
		expander.Write([]byte(info))
		expander.Write([]byte{counter})
		previous = expander.Sum(nil)
		out = append(out, previous...)
	}
	return out[:length], nil
}

var (
	b64    = base64.StdEncoding
	b64url = base64.RawURLEncoding
)

// NewContentKey returns a fresh 32-byte content key from the OS CSPRNG.
func NewContentKey() ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating a content key: %w", err)
	}
	return key, nil
}

// EncodeFragment encodes a content key as a URL fragment: "1" + base64url(key).
//
// Bare, with a single leading version character and no "k=" prefix. A key=value appendix reads
// as optional and invites link-mangling clients to truncate it, and a truncated fragment must
// fail closed rather than look like a well-formed link missing a part.
func EncodeFragment(contentKey []byte) (string, error) {
	if len(contentKey) != keyLen {
		return "", fmt.Errorf("a content key is %d bytes, got %d", keyLen, len(contentKey))
	}
	return "1" + b64url.EncodeToString(contentKey), nil
}

// DecodeFragment parses a fragment back into a content key.
//
// It returns ErrMissingKey when there is no fragment at all and ErrMalformedKey when there is
// one but it is not usable. The distinction is not pedantry: "your link is incomplete" and
// "this share expired" look identical on screen and have opposite remedies.
func DecodeFragment(fragment string) ([]byte, error) {
	text := strings.TrimLeft(fragment, "#")
	if text == "" {
		return nil, fmt.Errorf("%w: no key fragment was supplied", ErrMissingKey)
	}
	if text[0] != '1' {
		return nil, fmt.Errorf(
			"%w: unsupported fragment version %q; this link needs a newer client",
			ErrMalformedKey, string(text[0]),
		)
	}
	raw, err := b64url.DecodeString(text[1:])
	if err != nil {
		return nil, fmt.Errorf("%w: the key fragment is not valid base64url", ErrMalformedKey)
	}
	if len(raw) != keyLen {
		return nil, fmt.Errorf(
			"%w: a content key is %d bytes; this fragment decoded to %d, so the link is "+
				"probably truncated",
			ErrMalformedKey, keyLen, len(raw),
		)
	}
	return raw, nil
}

// contentCipher derives the AES-GCM cipher for a blob.
//
// The passcode goes into info, never into the salt. They serve different purposes, and a salt
// built from the passcode would make the derivation depend on a value that has to stay
// reproducible from stored data alone.
func contentCipher(contentKey, salt []byte, passcode *string) (cipher.AEAD, error) {
	info := "content"
	if passcode != nil {
		info = "content|" + *passcode
	}
	derived, err := hkdfDerive(contentKey, salt, info, keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// ValidateFields checks a field array against section 2.2.1 before it is encrypted.
//
// This exists because getting it wrong is invisible. A field object using "label" instead of
// "key" still encrypts, still posts, still decrypts and still renders — with every label blank
// and no error anywhere. Go's struct tags make the mistake harder than in the dynamic
// languages, but a caller building fields from a map[string]string or from JSON can still
// reach it, which is why the check exists here rather than only in the docs.
func ValidateFields(fields []Field) error {
	for i, field := range fields {
		if field.Key == "" {
			return fmt.Errorf("%w: field %d has no 'key' (its visible label)", ErrInvalidField, i)
		}
		if field.Type == "" {
			return fmt.Errorf("%w: field %d has no 'type'; one of %s", ErrInvalidField, i, strings.Join(FieldTypes, ", "))
		}
	}
	return nil
}

// EncryptOption customises encryption. The unexported fixed-parameter options exist for the
// conformance vectors; production code cannot reach them, which is deliberate — a reused IV
// under the same key destroys AES-GCM's guarantees outright.
type EncryptOption func(*encryptConfig)

type encryptConfig struct {
	passcode *string
	salt     []byte
	iv       []byte
}

// WithPasscode mixes a passcode into the key derivation. The passcode itself is never sent;
// the server receives only a one-way verifier.
func WithPasscode(passcode string) EncryptOption {
	return func(c *encryptConfig) { c.passcode = &passcode }
}

// EncryptContent encrypts a field array, returning the base64 blob the API accepts.
//
// The blob uses standard base64, not base64url: it travels in a JSON body, never in a URL.
func EncryptContent(contentKey []byte, fields []Field, opts ...EncryptOption) (string, error) {
	if err := ValidateFields(fields); err != nil {
		return "", err
	}

	cfg := &encryptConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	salt := cfg.salt
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("generating a salt: %w", err)
		}
	}
	iv := cfg.iv
	if iv == nil {
		iv = make([]byte, ivLen)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("generating an iv: %w", err)
		}
	}

	aead, err := contentCipher(contentKey, salt, cfg.passcode)
	if err != nil {
		return "", err
	}

	// encoding/json escapes <, > and & as \u003c, \u003e and \u0026 by default. The other
	// implementations do not, so a field containing any of them would produce a different
	// blob — decryptable here, byte-different from every other client, and caught only by the
	// conformance vectors if they happened to contain one. Turning the escaping off makes the
	// output match. The value is AEAD-sealed, so nothing downstream is interpreting it as HTML.
	var buf strings.Builder
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(fields); err != nil {
		return "", fmt.Errorf("serialising fields: %w", err)
	}
	// Encode appends a newline; the canonical form has none.
	plaintext := []byte(strings.TrimSuffix(buf.String(), "\n"))

	body := aead.Seal(nil, iv, plaintext, nil)

	out := make([]byte, 0, len(salt)+len(iv)+len(body))
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, body...)
	return b64.EncodeToString(out), nil
}

// DecryptContent decrypts a blob back into the field array.
//
// A wrong passcode and a tampered blob are indistinguishable, deliberately: both surface as
// ErrWireFormat. Telling them apart would hand an attacker an oracle.
func DecryptContent(contentKey []byte, blob string, passcode *string) ([]Field, error) {
	raw, err := b64.DecodeString(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: the content blob is not valid base64", ErrWireFormat)
	}

	minimum := saltLen + ivLen + tagLen
	if len(raw) < minimum {
		// Checked before anything else, so a truncated blob is reported as truncated rather
		// than as a decryption failure that sends somebody looking for a wrong passcode.
		return nil, fmt.Errorf(
			"%w: the content blob is %d bytes; the smallest possible one is %d",
			ErrWireFormat, len(raw), minimum,
		)
	}

	salt := raw[:saltLen]
	iv := raw[saltLen : saltLen+ivLen]
	body := raw[saltLen+ivLen:]

	aead, err := contentCipher(contentKey, salt, passcode)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, iv, body, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: could not decrypt: the passcode is wrong, or the content was altered",
			ErrWireFormat,
		)
	}

	var fields []Field
	if err := json.Unmarshal(plaintext, &fields); err != nil {
		return nil, fmt.Errorf("%w: decrypted content is not a field array", ErrWireFormat)
	}
	return fields, nil
}

// AccessToken derives the token the server uses to admit a reader.
//
// The salt is empty so this is reproducible from the fragment alone, on any device, with
// nothing stored. The server keeps only a hash of it and learns nothing about the content key,
// because HKDF's domain separation makes the "access" output independent of the "content" one.
func AccessToken(contentKey []byte) (string, error) {
	out, err := hkdfDerive(contentKey, nil, "access", keyLen)
	if err != nil {
		return "", err
	}
	return b64url.EncodeToString(out), nil
}

// PasscodeVerifier derives a one-way verifier that lets the server check a passcode it cannot
// use.
func PasscodeVerifier(passcode string) (string, error) {
	out, err := hkdfDerive([]byte(passcode), nil, "verify", keyLen)
	if err != nil {
		return "", err
	}
	return b64url.EncodeToString(out), nil
}

// A SeedKeypair is a P-256 keypair reconstructed from a 32-byte seed.
//
// Storing the seed rather than a serialized key is what lets an entire private key live in a
// URL fragment, and what lets ephemeral automation derive the same key with no local state.
type SeedKeypair struct {
	Seed            []byte
	Scalar          *big.Int
	PrivateKey      *ecdh.PrivateKey
	PublicKeyRaw    []byte
	PublicKeyB64URL string
}

var p256Order = elliptic.P256().Params().N

// KeypairFromSeed derives a P-256 keypair from a 32-byte seed (section 3).
//
// 48 bytes of HKDF output rather than 32 is deliberate: the extra 128 bits make the modular
// bias negligible. Reducing mod n-1 and adding one yields a scalar in [1, n-1], excluding
// zero, which is not a valid private key.
func KeypairFromSeed(seed []byte) (*SeedKeypair, error) {
	if len(seed) != keyLen {
		return nil, fmt.Errorf("a seed is %d bytes, got %d", keyLen, len(seed))
	}

	wide, err := hkdfDerive(seed, nil, "crs-ecdh-p256-scalar", 48)
	if err != nil {
		return nil, err
	}
	scalar := new(big.Int).SetBytes(wide)
	scalar.Mod(scalar, new(big.Int).Sub(p256Order, big.NewInt(1)))
	scalar.Add(scalar, big.NewInt(1))

	scalarBytes := make([]byte, keyLen)
	scalar.FillBytes(scalarBytes)

	private, err := ecdh.P256().NewPrivateKey(scalarBytes)
	if err != nil {
		return nil, fmt.Errorf("deriving the private key: %w", err)
	}
	public := private.PublicKey().Bytes()

	return &SeedKeypair{
		Seed:            seed,
		Scalar:          scalar,
		PrivateKey:      private,
		PublicKeyRaw:    public,
		PublicKeyB64URL: b64url.EncodeToString(public),
	}, nil
}

// CustodyKeypair derives the custody keypair from the third part of an API credential
// (section 3.1).
//
// The custody secret is never transmitted. It is a *separate* secret from the auth secret
// precisely so that the server cannot reconstruct this private key: the auth secret goes over
// the wire on every request, so deriving custody from it would mean the server *could*
// decrypt. Not that it would — that it could, which is what zero-knowledge is meant to remove.
//
// The empty salt is deliberate: the derivation has to be reproducible from the credential
// alone, on any machine, with nothing stored.
func CustodyKeypair(custodySecret string) (*SeedKeypair, error) {
	seed, err := hkdfDerive([]byte(custodySecret), nil, "custody", keyLen)
	if err != nil {
		return nil, err
	}
	return KeypairFromSeed(seed)
}

// WrapOption customises a wrap. As with EncryptOption, fixed parameters are reachable only
// from the conformance tests.
type WrapOption func(*wrapConfig)

type wrapConfig struct {
	ephemeralSeed []byte
	salt          []byte
	iv            []byte
}

// WrapToPublicKey wraps a payload to a published P-256 public key.
//
// Layout: base64(0x01 || ephemeralPublic(65) || salt(16) || iv(12) || ciphertext+tag).
// Wrapping a 32-byte payload gives exactly 142 bytes, which is a useful field check.
//
// The ephemeral keypair is fresh per wrap. Reusing one across wraps leaks the relationship
// between them.
func WrapToPublicKey(payload, recipientPublicKey []byte, opts ...WrapOption) (string, error) {
	if len(recipientPublicKey) != pubKeyLen || recipientPublicKey[0] != 0x04 {
		return "", fmt.Errorf(
			"a recipient public key is a %d-byte uncompressed P-256 point starting with 0x04",
			pubKeyLen,
		)
	}

	cfg := &wrapConfig{}
	for _, opt := range opts {
		opt(cfg)
	}

	ephemeralSeed := cfg.ephemeralSeed
	if ephemeralSeed == nil {
		ephemeralSeed = make([]byte, keyLen)
		if _, err := rand.Read(ephemeralSeed); err != nil {
			return "", fmt.Errorf("generating an ephemeral seed: %w", err)
		}
	}
	ephemeral, err := KeypairFromSeed(ephemeralSeed)
	if err != nil {
		return "", err
	}

	salt := cfg.salt
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return "", fmt.Errorf("generating a salt: %w", err)
		}
	}
	iv := cfg.iv
	if iv == nil {
		iv = make([]byte, ivLen)
		if _, err := rand.Read(iv); err != nil {
			return "", fmt.Errorf("generating an iv: %w", err)
		}
	}

	peer, err := ecdh.P256().NewPublicKey(recipientPublicKey)
	if err != nil {
		return "", fmt.Errorf("the recipient public key is not a valid P-256 point: %w", err)
	}
	shared, err := ephemeral.PrivateKey.ECDH(peer)
	if err != nil {
		return "", fmt.Errorf("ecdh: %w", err)
	}

	wrappingKey, err := hkdfDerive(shared, salt, "crs-request-submission", keyLen)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	body := aead.Seal(nil, iv, payload, nil)

	out := make([]byte, 0, 1+pubKeyLen+saltLen+ivLen+len(body))
	out = append(out, wrapVersion)
	out = append(out, ephemeral.PublicKeyRaw...)
	out = append(out, salt...)
	out = append(out, iv...)
	out = append(out, body...)
	return b64.EncodeToString(out), nil
}

// UnwrapWithSeed unwraps a payload with the seed whose public key it was wrapped to.
func UnwrapWithSeed(wrapped string, seed []byte) ([]byte, error) {
	raw, err := b64.DecodeString(wrapped)
	if err != nil {
		return nil, fmt.Errorf("%w: the wrap is not valid base64", ErrWireFormat)
	}

	header := 1 + pubKeyLen + saltLen + ivLen
	if len(raw) < header+tagLen {
		return nil, fmt.Errorf(
			"%w: a wrap is at least %d bytes; this one is %d",
			ErrWireFormat, header+tagLen, len(raw),
		)
	}
	if raw[0] != wrapVersion {
		return nil, fmt.Errorf(
			"%w: unsupported wrap version %d; this needs a newer client", ErrWireFormat, raw[0],
		)
	}

	ephemeralPublic := raw[1 : 1+pubKeyLen]
	salt := raw[1+pubKeyLen : 1+pubKeyLen+saltLen]
	iv := raw[1+pubKeyLen+saltLen : header]
	body := raw[header:]

	recipient, err := KeypairFromSeed(seed)
	if err != nil {
		return nil, err
	}
	peer, err := ecdh.P256().NewPublicKey(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("%w: the ephemeral public key is not a valid P-256 point", ErrWireFormat)
	}
	shared, err := recipient.PrivateKey.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}

	keyBytes, err := hkdfDerive(shared, salt, "crs-request-submission", keyLen)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	payload, err := aead.Open(nil, iv, body, nil)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: could not unwrap: wrong recipient key, or the wrap was altered", ErrWireFormat,
		)
	}
	return payload, nil
}
