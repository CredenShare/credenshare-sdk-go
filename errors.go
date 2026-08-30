package credenshare

import (
	"errors"
	"fmt"
)

// Sentinel errors, so callers can branch with errors.Is rather than on message text.
//
// Several of these look identical on screen and have opposite remedies — a link that arrived
// without its key versus a link that arrived damaged; a spent plan allowance versus a rate
// limit. Distinguishing them is the difference between a caller who knows what to do and one
// who retries forever.
var (
	// ErrMissingKey means a link arrived with no key at all.
	//
	// Usually something stripped the fragment: a chat client that "cleaned" the URL, a
	// redirect, a copy that stopped at the '#'. The remedy is to ask for the link again — not
	// to ask for the share to be recreated.
	ErrMissingKey = errors.New("no key in the link")

	// ErrMalformedKey means a key is present but unusable — truncated, or from a newer format.
	ErrMalformedKey = errors.New("the key in the link is unusable")

	// ErrWireFormat means content could not be read: a wrong passcode, or altered ciphertext.
	// The two are indistinguishable on purpose; telling them apart would hand an attacker an
	// oracle for guessing passcodes.
	ErrWireFormat = errors.New("the content could not be read")

	// ErrCredentialFormat means a credential is not in the expected shape.
	ErrCredentialFormat = errors.New("the credential is malformed")

	// ErrCustodySecretTransmitted fires at the request boundary if the custody secret was
	// about to leave the machine. If you see it, rotate the credential: the guarantee it
	// exists to provide — that the server *cannot* reconstruct the custody private key — is
	// gone the moment it reaches the wire.
	ErrCustodySecretTransmitted = errors.New("the custody secret was about to be transmitted")
)

// An APIError is any refusal from the API.
//
// Use errors.As to reach Status, Code and RequestID, and errors.Is against the sentinels below
// to branch on what to do about it.
type APIError struct {
	Message string
	Status  int
	// Code is the API's numeric error code, where it sends one.
	Code int
	// RequestID identifies the exact request in our logs. Quote it when reporting a problem.
	RequestID string
	// RetryAfter is seconds, set only on a rate limit.
	RetryAfter int

	kind error
}

func (e *APIError) Error() string {
	parts := fmt.Sprintf("HTTP %d", e.Status)
	if e.Code != 0 {
		parts += fmt.Sprintf(", code %d", e.Code)
	}
	if e.RequestID != "" {
		parts += fmt.Sprintf(", request %s", e.RequestID)
	}
	return fmt.Sprintf("%s (%s)", e.Message, parts)
}

// Unwrap exposes the sentinel so errors.Is works:
//
//	if errors.Is(err, credenshare.ErrQuotaExceeded) { ... }
func (e *APIError) Unwrap() error { return e.kind }

// The sentinels an APIError wraps. Each names a remedy, not just a status.
var (
	// ErrAuthentication: the credential is unknown, revoked or expired. Mint a new one.
	ErrAuthentication = errors.New("the credential was not accepted")

	// ErrPermission: valid credential, not allowed to do this — a missing scope, or a plan
	// without API access.
	ErrPermission = errors.New("this credential may not do that")

	// ErrNotFound: no such share on this account. A share belonging to another account
	// reports identically, on purpose, so a credential cannot be used to discover what other
	// accounts hold.
	ErrNotFound = errors.New("no such share on this account")

	// ErrRateLimited: too many requests. Check APIError.RetryAfter.
	ErrRateLimited = errors.New("too many requests")

	// ErrQuotaExceeded: the plan's share allowance is spent. Distinct from ErrRateLimited —
	// waiting does not help, and the fix is a plan change or expiring old shares.
	ErrQuotaExceeded = errors.New("the plan's share allowance is spent")

	// ErrIdempotencyConflict: an Idempotency-Key was reused with a different request body.
	//
	// Almost always this means a caller passed the same key to two separate Create calls
	// expecting the second to be a no-op. It cannot be, and no option makes it one:
	// encryption is randomised per call — a fresh salt and IV every time, which AES-GCM
	// requires — so two calls with identical arguments, and even with the same content key,
	// still produce different ciphertext. The API is right to refuse.
	//
	// What the header actually protects is a NETWORK retry, where the body is byte-identical
	// because it is the same already-encrypted request being sent again. This client performs
	// those retries itself.
	ErrIdempotencyConflict = errors.New("this Idempotency-Key was used with a different body")

	// ErrServiceUnavailable: entitlements could not be resolved, so nothing was created.
	// Transient and safe to retry. The API returns this rather than guessing, because
	// guessing "unlimited" would let an account exceed its plan and guessing "exhausted"
	// would break a healthy one during a billing hiccup.
	ErrServiceUnavailable = errors.New("the service could not resolve entitlements")
)
