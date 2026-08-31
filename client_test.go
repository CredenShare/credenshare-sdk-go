package credenshare

// Client behaviour, against a stub transport.
//
// The properties worth testing here are not "does it call the right URL" but the ones where
// being wrong is silent or dangerous: the custody secret never leaving the machine, the content
// key never appearing in a request, and errors that imply the right remedy.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testCredential = "crs_sk_live_abc123.authsecretvalue.custodysecretvalue"
	testTwoPart    = "crs_sk_live_abc123.authsecretvalue"
)

var testField = Field{Key: "k", Value: "v", Type: "text"}

// recorder is a RoundTripper that records requests and replays canned responses.
type recorder struct {
	requests  []recordedRequest
	responses []stubResponse
	failures  int // fail the first N attempts at the transport level
	attempts  int
}

type recordedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    string
}

type stubResponse struct {
	status  int
	body    any
	headers map[string]string
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.attempts++

	body := ""
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		body = string(raw)
	}
	r.requests = append(r.requests, recordedRequest{
		Method: req.Method, URL: req.URL.String(), Headers: req.Header.Clone(), Body: body,
	})

	if r.attempts <= r.failures {
		return nil, fmt.Errorf("connection reset")
	}

	stub := stubResponse{status: 201, body: map[string]any{"short_code": "abc123"}}
	if len(r.responses) > 0 {
		index := len(r.requests) - 1 - r.failures
		if index >= len(r.responses) {
			index = len(r.responses) - 1
		}
		stub = r.responses[index]
	}

	payload, _ := json.Marshal(stub.body)
	header := http.Header{"Content-Type": []string{"application/json"}}
	for key, value := range stub.headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode: stub.status,
		Body:       io.NopCloser(strings.NewReader(string(payload))),
		Header:     header,
	}, nil
}

func newTestClient(t *testing.T, rec *recorder, credential string) *Client {
	t.Helper()
	client, err := New(credential, &Options{
		LinkOrigin: "https://crs.sh",
		HTTPClient: &http.Client{Transport: rec},
		MaxRetries: Retries(2),
	})
	if err != nil {
		t.Fatalf("building the client: %v", err)
	}
	return client
}

// -- credential handling --------------------------------------------------------------

func TestCredentialParsesBothForms(t *testing.T) {
	three, err := ParseCredential(testCredential)
	if err != nil || three.KeyID != "abc123" || !three.HasCustody() {
		t.Fatalf("three-part: %v %+v", err, three)
	}
	two, err := ParseCredential(testTwoPart)
	if err != nil || two.HasCustody() {
		t.Fatalf("two-part: %v %+v", err, two)
	}
}

func TestMalformedCredentialsAreRefused(t *testing.T) {
	for _, bad := range []string{
		"", "nope", "crs_sk_live_onepart", "crs_sk_live_a.b.c.d", "crs_sk_live_a..c",
	} {
		if _, err := ParseCredential(bad); !errors.Is(err, ErrCredentialFormat) {
			t.Errorf("ParseCredential(%q) = %v, want ErrCredentialFormat", bad, err)
		}
	}
}

func TestACredentialNeverRendersItsSecrets(t *testing.T) {
	// A credential in a log line is a credential that has to be rotated, and %v on a struct is
	// how that usually happens. String and GoString both have to withhold them.
	credential, err := ParseCredential(testCredential)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", credential),
		fmt.Sprintf("%s", credential),
		fmt.Sprintf("%#v", credential),
	} {
		if strings.Contains(rendered, "authsecretvalue") || strings.Contains(rendered, "custodysecretvalue") {
			t.Errorf("a secret appeared in %q", rendered)
		}
		if !strings.Contains(rendered, "abc123") {
			t.Errorf("the key id is missing from %q", rendered)
		}
	}
}

func TestTheCustodySecretIsNeverTransmitted(t *testing.T) {
	// THE property of the split credential. The custody half exists so the server CANNOT
	// reconstruct the private key. If it reaches the wire that guarantee is gone.
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.CreateShare(context.Background(), CreateParams{
		Title: "t", Fields: []Field{testField},
	}); err != nil {
		t.Fatal(err)
	}

	request := rec.requests[0]
	everything := request.URL + request.Body + fmt.Sprint(request.Headers)
	if strings.Contains(everything, "custodysecretvalue") {
		t.Fatal("the custody secret reached the wire")
	}
	if got := request.Headers.Get("Authorization"); got != "Bearer "+testTwoPart {
		t.Fatalf("Authorization = %q", got)
	}
}

func TestCustodyPublicKeyIsDerivedLocally(t *testing.T) {
	credential, err := ParseCredential(testCredential)
	if err != nil {
		t.Fatal(err)
	}
	got, err := credential.CustodyPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	want, err := CustodyKeypair("custodysecretvalue")
	if err != nil {
		t.Fatal(err)
	}
	if got != want.PublicKeyB64URL {
		t.Fatalf("got %s, want %s", got, want.PublicKeyB64URL)
	}
}

// -- create ---------------------------------------------------------------------------

func TestCreateSendsCiphertextAndNeverTheKey(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 201, body: map[string]any{"short_code": "xy12"}}}}
	client := newTestClient(t, rec, testCredential)

	share, err := client.CreateShare(context.Background(), CreateParams{
		Title:  "Staging deploy credentials",
		Fields: []Field{{Key: "Password", Value: "correct horse", Type: "password"}},
	})
	if err != nil {
		t.Fatal(err)
	}

	body := rec.requests[0].Body
	if strings.Contains(body, "correct horse") {
		t.Fatal("the plaintext was sent")
	}
	if strings.Contains(body, b64url.EncodeToString(share.ContentKey)) {
		t.Fatal("the content key was sent")
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["encryption_type"] != encryptionType {
		t.Fatalf("encryption_type = %v", parsed["encryption_type"])
	}

	// But the blob must decrypt with the key the caller was handed.
	fields, err := DecryptContent(share.ContentKey, parsed["data"].(string), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || fields[0].Value != "correct horse" {
		t.Fatalf("decrypted %+v", fields)
	}
}

func TestTheLinkCarriesTheKeyInItsFragment(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 201, body: map[string]any{"short_code": "xy12"}}}}
	client := newTestClient(t, rec, testCredential)

	share, err := client.CreateShare(context.Background(), CreateParams{Title: "t", Fields: []Field{testField}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(share.Link, "https://crs.sh/xy12#") {
		t.Fatalf("link = %s", share.Link)
	}
	key, err := DecodeFragment(strings.SplitN(share.Link, "#", 2)[1])
	if err != nil || string(key) != string(share.ContentKey) {
		t.Fatalf("fragment did not round-trip: %v", err)
	}
}

func TestTheShareStringWithholdsTheLink(t *testing.T) {
	// The link IS the secret; printing a Share should not spill it into a log.
	share := &Share{ShortCode: "xy12", Link: "https://crs.sh/xy12#1AAA"}
	if strings.Contains(share.String(), "#") {
		t.Fatalf("String() = %s", share.String())
	}
}

func TestCreateAlwaysSendsAnIdempotencyKey(t *testing.T) {
	// Required by the API. A retried automation must not silently create a second copy of a
	// credential in the world, with its own link and audit trail.
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateShare(context.Background(), CreateParams{Title: "t", Fields: []Field{testField}}); err != nil {
		t.Fatal(err)
	}
	if rec.requests[0].Headers.Get("Idempotency-Key") == "" {
		t.Fatal("no Idempotency-Key was sent")
	}
}

func TestAPasscodeSendsAVerifierAndNeverThePasscode(t *testing.T) {
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateShare(context.Background(), CreateParams{
		Title: "t", Fields: []Field{testField}, Passcode: "hunter2",
	}); err != nil {
		t.Fatal(err)
	}

	body := rec.requests[0].Body
	if strings.Contains(body, "hunter2") {
		t.Fatal("the passcode was sent")
	}
	want, err := PasscodeVerifier("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, want) {
		t.Fatal("the verifier was not sent")
	}
}

func TestAFieldWithNoKeyIsRefusedBeforeAnyRequest(t *testing.T) {
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	_, err := client.CreateShare(context.Background(), CreateParams{
		Title: "t", Fields: []Field{{Value: "v", Type: "password"}},
	})
	if err == nil || !strings.Contains(err.Error(), "visible label") {
		t.Fatalf("got %v, want a refusal", err)
	}
	if len(rec.requests) != 0 {
		t.Fatal("something was sent")
	}
}

// -- reads ----------------------------------------------------------------------------

func TestListCarriesItsPagingFigures(t *testing.T) {
	// A caller who has to guess whether more exists guesses wrong.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"shares":     []any{map[string]any{"short_code": "a1"}},
		"pagination": map[string]any{"page": 1, "limit": 2, "total": 5, "total_pages": 3},
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListShares(context.Background(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || page.TotalPages != 3 || !page.HasMore() {
		t.Fatalf("page = %+v", page)
	}
	if page.Shares[0].ShortCode != "a1" {
		t.Fatalf("shares = %+v", page.Shares)
	}
}

func TestIterateDoesNotStopOnAShortMiddlePage(t *testing.T) {
	// The bug in every hand-rolled version of this loop. A server may return a page shorter
	// than the limit in the MIDDLE of a result set; stopping there silently truncates.
	page := func(codes []string, number int) stubResponse {
		rows := make([]any, 0, len(codes))
		for _, code := range codes {
			rows = append(rows, map[string]any{"short_code": code})
		}
		return stubResponse{status: 200, body: map[string]any{
			"shares":     rows,
			"pagination": map[string]any{"page": number, "limit": 2, "total": 5, "total_pages": 3},
		}}
	}
	rec := &recorder{responses: []stubResponse{
		page([]string{"a1", "a2"}, 1), page([]string{"b1"}, 2), page([]string{"c1", "c2"}, 3),
	}}
	client := newTestClient(t, rec, testCredential)

	var seen []string
	if err := client.IterateShares(context.Background(), 2, func(s ShareSummary) error {
		seen = append(seen, s.ShortCode)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if strings.Join(seen, ",") != "a1,a2,b1,c1,c2" {
		t.Fatalf("walked %v", seen)
	}
	if len(rec.requests) != 3 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
}

func TestExpireIssuesADelete(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)
	if err := client.ExpireShare(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	if rec.requests[0].Method != http.MethodDelete || !strings.HasSuffix(rec.requests[0].URL, "/shares/a1") {
		t.Fatalf("request = %+v", rec.requests[0])
	}
}

func TestReadLinkIsRefusedWithAReason(t *testing.T) {
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.ReadLink("https://crs.sh/abc#1AAA"); err == nil ||
		!strings.Contains(err.Error(), "by design") {
		t.Fatalf("got %v", err)
	}
}

// -- errors imply remedies --------------------------------------------------------------

func TestErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		body   map[string]any
		want   error
	}{
		{401, map[string]any{"message": "bad credential"}, ErrAuthentication},
		{403, map[string]any{"message": "no api access"}, ErrPermission},
		{403, map[string]any{"message": "limit reached", "error_code": 61}, ErrQuotaExceeded},
		{404, map[string]any{"message": "not found"}, ErrNotFound},
		{409, map[string]any{"message": "already used", "error_code": 105}, ErrIdempotencyConflict},
		{503, map[string]any{"message": "unavailable"}, ErrServiceUnavailable},
	}

	for _, testCase := range cases {
		rec := &recorder{responses: []stubResponse{{status: testCase.status, body: testCase.body}}}
		client := newTestClient(t, rec, testCredential)
		_, err := client.ListShares(context.Background(), 10, 1)
		if !errors.Is(err, testCase.want) {
			t.Errorf("status %d gave %v, want %v", testCase.status, err, testCase.want)
		}
	}
}

func TestASpentQuotaIsNotARateLimit(t *testing.T) {
	// Both are refusals, but waiting fixes one and not the other.
	rec := &recorder{responses: []stubResponse{{status: 403, body: map[string]any{"error_code": 61}}}}
	client := newTestClient(t, rec, testCredential)
	_, err := client.ListShares(context.Background(), 10, 1)
	if !errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("got %v", err)
	}
}

func TestRateLimitExposesRetryAfter(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{
		status: 429, body: map[string]any{"message": "slow down"},
		headers: map[string]string{"Retry-After": "42"},
	}}}
	client := newTestClient(t, rec, testCredential)
	_, err := client.ListShares(context.Background(), 10, 1)

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.RetryAfter != 42 {
		t.Fatalf("got %v", err)
	}
}

// -- transport retries -------------------------------------------------------------------

func TestADroppedConnectionIsRetriedWithTheIdenticalRequest(t *testing.T) {
	// The case the mandatory header exists for. The retry must repeat the identical body, or
	// the server sees a new one under a used key and refuses — turning a recoverable blip into
	// a hard failure. It is also where a consumed io.Reader would silently send an empty body.
	rec := &recorder{failures: 1, responses: []stubResponse{{status: 201, body: map[string]any{"short_code": "xy12"}}}}
	client := newTestClient(t, rec, testCredential)

	share, err := client.CreateShare(context.Background(), CreateParams{Title: "t", Fields: []Field{testField}})
	if err != nil {
		t.Fatal(err)
	}
	if share.ShortCode != "xy12" {
		t.Fatalf("short code = %s", share.ShortCode)
	}
	if len(rec.requests) != 2 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
	if rec.requests[0].Body != rec.requests[1].Body {
		t.Fatal("the retried body differed from the first")
	}
	if rec.requests[0].Body == "" {
		t.Fatal("the first body was empty")
	}
	if rec.requests[0].Headers.Get("Idempotency-Key") != rec.requests[1].Headers.Get("Idempotency-Key") {
		t.Fatal("the retry used a different Idempotency-Key")
	}
}

func TestAnHTTP500IsNotRetried(t *testing.T) {
	// It may have committed, and this client cannot tell. Retrying would risk a second copy of
	// a credential in the world under a caller who believes one was created.
	rec := &recorder{responses: []stubResponse{{status: 500, body: map[string]any{"message": "boom"}}}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateShare(context.Background(), CreateParams{Title: "t", Fields: []Field{testField}}); err == nil {
		t.Fatal("expected an error")
	}
	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
}

// A transport failure is NOT ErrServiceUnavailable. That sentinel is documented as "nothing
// was created", which is an answer from the API; never getting one is not that answer. Go's
// Do returns once headers arrive, so a failure there can still mean the request was written
// and processed - which is exactly why the honest sentinel is ErrDeliveryUnknown.
func TestRetriesAreBoundedAndReportAnUnknownOutcome(t *testing.T) {
	rec := &recorder{failures: 99}
	client, err := New(testCredential, &Options{
		HTTPClient: &http.Client{Transport: rec},
		MaxRetries: Retries(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	err = func() error { _, e := client.ListShares(context.Background(), 10, 1); return e }()
	if !errors.Is(err, ErrDeliveryUnknown) {
		t.Fatalf("got %v", err)
	}
	if errors.Is(err, ErrServiceUnavailable) {
		t.Fatal("a transport failure must not claim the API said nothing was created")
	}
	if rec.attempts != 2 {
		t.Fatalf("made %d attempts", rec.attempts)
	}
}
