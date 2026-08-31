package credenshare

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

// Every *APIError must match ErrAPI, because errors.go and the README both describe it as the
// catch-all a caller falls back to.
//
// Before Is() existed, Unwrap only ever yielded the SPECIFIC sentinel, so errors.Is(err,
// ErrAPI) was true for exactly the shapes whose kind happened to be ErrAPI - four of ten.
// A caller using it as the default arm of a type switch silently skipped 401, 403, 404, 429
// and 503, which are the five most common refusals there are.
func TestEveryRefusalMatchesErrAPI(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		code     int
		specific error
	}{
		{"401 unauthorized", http.StatusUnauthorized, 0, ErrAuthentication},
		{"403 forbidden", http.StatusForbidden, 0, ErrPermission},
		{"403 quota", http.StatusForbidden, quotaExceededCode, ErrQuotaExceeded},
		{"404 not found", http.StatusNotFound, 0, ErrNotFound},
		{"409 idempotency", http.StatusConflict, idempotencyConflictCode, ErrIdempotencyConflict},
		{"409 other", http.StatusConflict, 0, nil},
		{"429 rate limited", http.StatusTooManyRequests, 0, ErrRateLimited},
		{"503 unavailable", http.StatusServiceUnavailable, 0, ErrServiceUnavailable},
		{"400 bad request", http.StatusBadRequest, 0, nil},
		{"500 server error", http.StatusInternalServerError, 0, nil},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parsed := map[string]any{"message": "refused"}
			if c.code != 0 {
				parsed["error_code"] = float64(c.code)
			}
			response := &http.Response{StatusCode: c.status, Header: http.Header{}}
			err := errorFor(response, parsed, []byte(`{"message":"refused"}`))

			if !errors.Is(err, ErrAPI) {
				t.Fatalf("errors.Is(err, ErrAPI) is false for %s - the documented catch-all misses it", c.name)
			}
			if c.specific != nil && !errors.Is(err, c.specific) {
				t.Fatalf("the specific sentinel stopped matching for %s", c.name)
			}
		})
	}
}

// Widening the catch-all must not make unrelated sentinels match.
func TestErrAPIDoesNotSwallowUnrelatedSentinels(t *testing.T) {
	response := &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}}
	err := errorFor(response, map[string]any{"message": "no"}, nil)

	for _, wrong := range []error{ErrAuthentication, ErrQuotaExceeded, ErrRateLimited, ErrMissingKey} {
		if errors.Is(err, wrong) {
			t.Fatalf("a 404 matched %v", wrong)
		}
	}
}

// Field lost `==` when Extra was added. Equal is the replacement, and it has to behave.
func TestFieldEqual(t *testing.T) {
	base := Field{Key: "k", Value: "v", Type: "text"}
	if !base.Equal(Field{Key: "k", Value: "v", Type: "text"}) {
		t.Fatal("identical fields compare unequal")
	}
	for _, other := range []Field{
		{Key: "x", Value: "v", Type: "text"},
		{Key: "k", Value: "x", Type: "text"},
		{Key: "k", Value: "v", Type: "password"},
	} {
		if base.Equal(other) {
			t.Fatalf("%+v compared equal to %+v", base, other)
		}
	}

	withExtra := Field{Key: "k", Value: "v", Type: "text", Extra: map[string]json.RawMessage{"a": json.RawMessage(`1`)}}
	if base.Equal(withExtra) || withExtra.Equal(base) {
		t.Fatal("a field with an unknown member equals one without")
	}
	same := Field{Key: "k", Value: "v", Type: "text", Extra: map[string]json.RawMessage{"a": json.RawMessage(`1`)}}
	if !withExtra.Equal(same) {
		t.Fatal("identical unknown members compare unequal")
	}
	differs := Field{Key: "k", Value: "v", Type: "text", Extra: map[string]json.RawMessage{"a": json.RawMessage(`2`)}}
	if withExtra.Equal(differs) {
		t.Fatal("differing unknown members compare equal")
	}
}
