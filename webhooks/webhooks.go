// Package webhooks verifies CredenShare webhook deliveries.
//
// A signature you do not check is decoration. This package exists so that checking one is
// easier than not checking it — including the parts people usually skip, which are the parts
// that matter.
package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SignatureHeader carries the timestamp and signatures.
const SignatureHeader = "X-CredenShare-Signature"

// DefaultTolerance is how far a delivery's timestamp may sit from your clock, in either
// direction.
//
// Symmetric because a receiver's clock can be behind OR ahead, and rejecting only one
// direction fails for half the machines that are wrong. Five minutes is long enough to survive
// ordinary drift and short enough that a captured delivery is not replayable for long.
const DefaultTolerance = 5 * time.Minute

// ErrVerification is returned for every refusal. Treat it as a forgery, not as a transient
// error; the wrapped message says which check failed.
var ErrVerification = errors.New("the webhook delivery did not verify")

// NoTolerance is a convenience for Options.Tolerance meaning "the timestamp must be exact".
func NoTolerance() *time.Duration { return new(time.Duration) }

// ToleranceOf returns a pointer to d, for setting Options.Tolerance inline.
func ToleranceOf(d time.Duration) *time.Duration { return &d }

// Options tune verification. The zero value uses DefaultTolerance and the current clock.
type Options struct {
	// Tolerance is a pointer so that a zero Duration means "accept no drift" rather than
	// "unset". Use NoTolerance for the strict case.
	Tolerance *time.Duration
	// Now is for tests. Zero means time.Now().
	Now time.Time
}

// Verify checks a delivery signature.
//
// payload must be the RAW request body, exactly as received. Re-serialising parsed JSON
// changes the bytes — key order, spacing, escapes — and the signature will not match. It is
// the single most common reason a correct implementation appears broken. Read the body with
// io.ReadAll before decoding it, and verify those bytes.
//
// secrets accepts one secret or several. Pass BOTH during a rotation: for 24 hours after you
// rotate, deliveries are signed with the old and new secrets together, so a receiver holding
// either keeps working while you roll your configuration.
//
// It returns nil on success and an error wrapping ErrVerification otherwise. There is no bool
// return: a (bool, error) signature invites `ok, _ := Verify(...)`, and a receiver that
// ignores the error accepts everything while looking like it checks.
func Verify(payload []byte, header string, secrets []string, opts *Options) error {
	candidates := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if strings.TrimSpace(secret) != "" {
			candidates = append(candidates, secret)
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("%w: no signing secret was supplied", ErrVerification)
	}

	timestamp, signatures, err := parse(header)
	if err != nil {
		return err
	}

	if opts == nil {
		opts = &Options{}
	}
	// A pointer so that 0 means "accept no drift at all" rather than "unset". With a
	// plain Duration the two are indistinguishable, so a caller pinning the clock in a
	// test silently got the five-minute default and the test proved nothing.
	tolerance := DefaultTolerance
	if opts.Tolerance != nil {
		tolerance = *opts.Tolerance
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	// The timestamp is checked BEFORE the signatures, and it is inside the signed material, so
	// it cannot be swapped for a fresh one without invalidating the MAC. Verifying the
	// signature but ignoring the timestamp would let anyone who captured one delivery replay
	// it forever.
	drift := now.Unix() - timestamp
	if drift < 0 {
		drift = -drift
	}
	if drift > int64(tolerance.Seconds()) {
		return fmt.Errorf(
			"%w: the delivery timestamp is %ds from this clock, outside the %.0fs window; "+
				"it may be a replay, or a clock may be wrong",
			ErrVerification, drift, tolerance.Seconds(),
		)
	}

	signed := append([]byte(strconv.FormatInt(timestamp, 10)+"."), payload...)

	for _, secret := range candidates {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(signed)
		expected := mac.Sum(nil)
		for _, candidate := range signatures {
			provided, err := hex.DecodeString(candidate)
			if err != nil {
				continue
			}
			// Constant time: a byte-by-byte comparison leaks how much of a guess was right,
			// which is enough to forge a signature given enough attempts.
			if hmac.Equal(expected, provided) {
				return nil
			}
		}
	}

	return fmt.Errorf(
		"%w: no signature matched. If you are mid-rotation, pass both secrets; otherwise "+
			"check you are verifying the RAW body rather than re-serialised JSON",
		ErrVerification,
	)
}

func parse(header string) (int64, []string, error) {
	if strings.TrimSpace(header) == "" {
		return 0, nil, fmt.Errorf("%w: the %s header is missing", ErrVerification, SignatureHeader)
	}

	var timestamp int64
	haveTimestamp := false
	var signatures []string

	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch key {
		case "t":
			parsed, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return 0, nil, fmt.Errorf(
					"%w: the timestamp %q is not a unix time", ErrVerification, value,
				)
			}
			timestamp = parsed
			haveTimestamp = true
		case "v1":
			// Several v1 entries is normal, not an error: it is how a rotation grace window is
			// expressed, so a receiver holding either secret keeps verifying.
			signatures = append(signatures, value)
		}
	}

	if !haveTimestamp {
		return 0, nil, fmt.Errorf("%w: the signature header carries no timestamp", ErrVerification)
	}
	if len(signatures) == 0 {
		return 0, nil, fmt.Errorf("%w: the signature header carries no v1 signature", ErrVerification)
	}
	return timestamp, signatures, nil
}
