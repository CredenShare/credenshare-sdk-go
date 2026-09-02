package credenshare

// The secure-request surface, against the same stub transport the share tests use.
//
// The properties worth asserting are the ones where being wrong is silent: the seed never
// leaving the machine, the public key going out in the encoding the API actually parses, a
// sealed submission opening with the seed that was kept, and paging that terminates.

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

var testPrompt = RequestField{Item: "Staging database password", Type: "password"}

// requestStub is the 201 body the API answers a create with.
func requestStub(shortCode, publicKey string) stubResponse {
	return stubResponse{status: 201, body: map[string]any{
		"short_code": shortCode,
		"expired_at": "2026-10-02T00:00:00Z",
		"public_key": publicKey,
	}}
}

// -- create ---------------------------------------------------------------------------

func TestCreateRequestReturnsTheSeedAndNeverTransmitsIt(t *testing.T) {
	// THE property of the feature. The seed is the entire read capability for every
	// submission this request will ever collect; if it reaches the wire, the guarantee that
	// we cannot read them is gone, and no error anywhere would say so.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)

	created, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title:  "Onboarding credentials",
		Fields: []RequestField{testPrompt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Seed) != 32 {
		t.Fatalf("seed is %d bytes", len(created.Seed))
	}
	if created.ShortCode != "rq12" {
		t.Fatalf("short code = %s", created.ShortCode)
	}

	request := rec.requests[0]
	everything := request.URL + request.Body + fmt.Sprint(request.Headers)
	for name, encoded := range map[string]string{
		"hex":             hex.EncodeToString(created.Seed),
		"standard base64": base64.StdEncoding.EncodeToString(created.Seed),
		"base64url":       base64.RawURLEncoding.EncodeToString(created.Seed),
		"raw bytes":       string(created.Seed),
	} {
		if strings.Contains(everything, encoded) {
			t.Fatalf("the seed reached the wire as %s", name)
		}
	}

	// But the public half must be there, and must be the one this seed derives.
	var parsed map[string]any
	if err := json.Unmarshal([]byte(request.Body), &parsed); err != nil {
		t.Fatal(err)
	}
	keypair, err := KeypairFromSeed(created.Seed)
	if err != nil {
		t.Fatal(err)
	}
	if parsed["public_key"] != keypair.PublicKeyB64URL {
		t.Fatalf("public_key = %v", parsed["public_key"])
	}
	if created.PublicKey != keypair.PublicKeyB64URL {
		t.Fatalf("SecureRequest.PublicKey = %s", created.PublicKey)
	}
}

func TestThePublicKeyTravelsAsUnpaddedBase64URL(t *testing.T) {
	// THE encoding trap on this feature: the public key goes out as unpadded base64url while
	// a submission's blob comes back as padded standard base64. Sending the wrong one is a
	// 201 followed by a request nobody's browser can encrypt to.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt},
	}); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rec.requests[0].Body), &parsed); err != nil {
		t.Fatal(err)
	}
	encoded, ok := parsed["public_key"].(string)
	if !ok {
		t.Fatalf("public_key = %v", parsed["public_key"])
	}
	if len(encoded) != 87 {
		t.Fatalf("public_key is %d characters, want 87 for a 65-byte point", len(encoded))
	}
	if strings.ContainsAny(encoded, "=+/") {
		t.Fatalf("public_key is padded or standard-alphabet: %s", encoded)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("public_key is not unpadded base64url: %v", err)
	}
	if len(raw) != 65 || raw[0] != 0x04 {
		t.Fatalf("decoded to %d bytes starting %#x", len(raw), raw[0])
	}
}

func TestACallerSuppliedSeedReproducesTheSameKeypair(t *testing.T) {
	// The custody-derived runner: an ephemeral container derives its seed from the
	// credential and rebuilds the same read capability with no local state.
	custody, err := CustodyKeypair("custodysecretvalue")
	if err != nil {
		t.Fatal(err)
	}

	rec := &recorder{responses: []stubResponse{requestStub("rq12", ""), requestStub("rq34", "")}}
	client := newTestClient(t, rec, testCredential)

	first, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt}, Seed: custody.Seed,
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt}, Seed: custody.Seed,
	})
	if err != nil {
		t.Fatal(err)
	}

	if first.PublicKey != custody.PublicKeyB64URL {
		t.Fatalf("public key = %s, want %s", first.PublicKey, custody.PublicKeyB64URL)
	}
	if second.PublicKey != first.PublicKey {
		t.Fatal("the same seed produced two different public keys")
	}
	if string(first.Seed) != string(custody.Seed) {
		t.Fatal("the supplied seed was not the one returned")
	}
}

// fixedSeed is a seed whose STANDARD base64 spelling uses the characters base64url does not.
// All-0xFF encodes as "///..." in the standard alphabet and "___..." in the URL-safe one, so
// a check that only knew one alphabet would miss the other.
func fixedSeed() []byte {
	seed := make([]byte, SeedLength)
	for i := range seed {
		seed[i] = 0xFF
	}
	return seed
}

func TestSeedLengthIsExportedAndIsThirtyTwo(t *testing.T) {
	// A caller who stores a seed has to validate it on the way back in, and the alternative
	// is a literal 32 in their code that nothing here would ever correct.
	if SeedLength != 32 {
		t.Fatalf("SeedLength = %d", SeedLength)
	}
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != SeedLength {
		t.Fatalf("NewSeed returned %d bytes", len(seed))
	}
}

func TestASeedInTheBodyIsRefusedBeforeAnythingIsSent(t *testing.T) {
	// The guarantee this feature rests on, asserted rather than trusted to the field list:
	// the serialized body is scanned, so a seed that arrived through a title, a description
	// or a prompt is caught too. Every encoding somebody hand-rolling that would reach for,
	// including the UNPADDED STANDARD base64 spelling that is neither of the obvious two.
	seed := fixedSeed()
	standard := base64.StdEncoding.EncodeToString(seed)

	for name, params := range map[string]CreateRequestParams{
		"base64url in the description": {
			Title:       "t",
			Fields:      []RequestField{testPrompt},
			Seed:        seed,
			Description: base64.RawURLEncoding.EncodeToString(seed),
		},
		"hex in the title": {
			Title:  hex.EncodeToString(seed),
			Fields: []RequestField{testPrompt},
			Seed:   seed,
		},
		"padded standard base64 in a prompt": {
			Title:  "t",
			Fields: []RequestField{{Item: standard, Type: "text"}},
			Seed:   seed,
		},
		"unpadded standard base64 in the description": {
			Title:       "t",
			Fields:      []RequestField{testPrompt},
			Seed:        seed,
			Description: strings.TrimRight(standard, "="),
		},
	} {
		rec := &recorder{}
		client := newTestClient(t, rec, testCredential)
		_, err := client.CreateRequest(context.Background(), params)
		if !errors.Is(err, ErrRequestSeedTransmitted) {
			t.Errorf("%s: got %v, want ErrRequestSeedTransmitted", name, err)
		}
		if len(rec.requests) != 0 {
			t.Errorf("%s: %d requests were sent anyway", name, len(rec.requests))
		}
	}
}

func TestASeedInTheIdempotencyKeyIsRefusedToo(t *testing.T) {
	// The body is not the only thing that leaves: the Idempotency-Key is caller-supplied and
	// travels as a HEADER. A caller who wants a deterministic key to match a deterministic
	// seed has the seed in hand, and a scan of the body alone would watch the front door
	// while the seed went out of the back.
	seed := fixedSeed()
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)

	_, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title:          "t",
		Fields:         []RequestField{testPrompt},
		Seed:           seed,
		IdempotencyKey: "deploy-" + base64.RawURLEncoding.EncodeToString(seed),
	})
	if !errors.Is(err, ErrRequestSeedTransmitted) {
		t.Fatalf("got %v, want ErrRequestSeedTransmitted", err)
	}
	if !strings.Contains(err.Error(), idempotencyHeader) {
		t.Fatalf("the error does not name the header it fired on: %v", err)
	}
	if len(rec.requests) != 0 {
		t.Fatalf("%d requests were sent anyway", len(rec.requests))
	}
}

func TestAWrongLengthSeedIsATypedErrorBeforeAnyCrypto(t *testing.T) {
	// Checked before the keypair is derived, so a truncated stored seed is an SDK error a
	// caller can branch on rather than whatever the crypto primitive underneath raises.
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)

	for _, length := range []int{1, 31, 33, 64} {
		_, err := client.CreateRequest(context.Background(), CreateRequestParams{
			Title: "t", Fields: []RequestField{testPrompt}, Seed: make([]byte, length),
		})
		if !errors.Is(err, ErrMalformedKey) {
			t.Errorf("a %d-byte seed gave %v, want ErrMalformedKey", length, err)
		}
	}
	if len(rec.requests) != 0 {
		t.Fatalf("%d requests were sent anyway", len(rec.requests))
	}
}

func TestTheTwoLinksAreBuiltTheWayTheApplicationBuildsThem(t *testing.T) {
	// Neither link is derivable from any API response: the /r/ segment and the origin belong
	// to the application, and the access fragment is version-prefixed. Hand-assembly is
	// exactly where the prefix gets left off, and a link missing it fails as though the
	// request were gone.
	seed := fixedSeed()
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)

	if got := client.CollectLinkFor("rq12"); got != "https://crs.sh/r/rq12" {
		t.Fatalf("CollectLinkFor = %s", got)
	}
	access, err := client.AccessLinkFor("rq12", seed)
	if err != nil {
		t.Fatal(err)
	}
	want := "https://crs.sh/r/rq12#1" + base64.RawURLEncoding.EncodeToString(seed)
	if access != want {
		t.Fatalf("AccessLinkFor = %s, want %s", access, want)
	}
	// The share link is a different path on the same origin, and mixing them up hands a
	// recipient a form instead of a secret.
	if strings.Contains(client.CollectLinkFor("rq12"), "/r/r/") {
		t.Fatal("the collect path is doubled")
	}

	if _, err := client.AccessLinkFor("rq12", seed[:31]); !errors.Is(err, ErrMalformedKey) {
		t.Fatalf("a short seed gave %v, want ErrMalformedKey", err)
	}

	created, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt}, Seed: seed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.CollectLink != "https://crs.sh/r/rq12" || created.AccessLink != want {
		t.Fatalf("created = collect %q access %q", created.CollectLink, created.AccessLink)
	}
	// And neither link reached the wire: the collect link is not a secret, but there is no
	// reason to send it, and the access link is the seed.
	sent := rec.requests[0].URL + rec.requests[0].Body + fmt.Sprint(rec.requests[0].Headers)
	if strings.Contains(sent, "/r/rq12") {
		t.Fatalf("a link was transmitted: %s", sent)
	}
}

func TestARequestWithholdsItsSeedFromEverySerializationPath(t *testing.T) {
	// A seed in a log line is every submission to that request, readable forever, and the
	// leak is silent: nothing errors, the line just contains the read capability.
	//
	// So every path a Go developer reaches for reflexively is asserted here, not only fmt.
	// json.Marshal serializes an exported []byte as base64 with nothing looking wrong, and
	// slog with a JSON handler resolves the field itself without consulting String. Both
	// leaked the seed in full before the methods this test covers existed.
	//
	// Pointer AND dereferenced value, because a method on a pointer receiver is absent from
	// a copy's method set - which is exactly how a redaction test passes while a %+v of a
	// copied struct prints the secret.
	seed := []byte("0123456789abcdef0123456789abcdef")
	created := &SecureRequest{
		ShortCode:   "rq12",
		Seed:        seed,
		PublicKey:   "BASE64URLPUBLICKEY",
		CollectLink: "https://crs.sh/r/rq12",
		AccessLink:  "https://crs.sh/r/rq12#1" + base64.RawURLEncoding.EncodeToString(seed),
	}
	copied := *created

	var logged strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("created a request", "request", created)
	logger.Info("created a request", "request", copied)

	asJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	asJSONValue, err := json.Marshal(copied)
	if err != nil {
		t.Fatal(err)
	}
	inASlice, err := json.Marshal([]SecureRequest{copied})
	if err != nil {
		t.Fatal(err)
	}

	renderings := map[string]string{
		"%v on the pointer":        fmt.Sprintf("%v", created),
		"%v on a copy":             fmt.Sprintf("%v", copied),
		"%+v on the pointer":       fmt.Sprintf("%+v", created),
		"%+v on a copy":            fmt.Sprintf("%+v", copied),
		"%+v on a dereference":     fmt.Sprintf("%+v", *created),
		"%#v on the pointer":       fmt.Sprintf("%#v", created),
		"%#v on a copy":            fmt.Sprintf("%#v", copied),
		"%s on the pointer":        fmt.Sprintf("%s", created),
		"%s on a copy":             fmt.Sprintf("%s", copied),
		"a slice of them":          fmt.Sprintf("%v", []SecureRequest{copied}),
		"json.Marshal(pointer)":    string(asJSON),
		"json.Marshal(copy)":       string(asJSONValue),
		"json.Marshal(slice)":      string(inASlice),
		"slog with a JSON handler": logged.String(),
	}
	spellings := map[string]string{
		"raw bytes":                string(seed),
		"decimal bytes":            fmt.Sprintf("%d", seed),
		"hex":                      hex.EncodeToString(seed),
		"padded standard base64":   base64.StdEncoding.EncodeToString(seed),
		"unpadded standard base64": strings.TrimRight(base64.StdEncoding.EncodeToString(seed), "="),
		"base64url":                base64.RawURLEncoding.EncodeToString(seed),
	}

	for path, rendered := range renderings {
		for encoding, spelling := range spellings {
			if strings.Contains(rendered, spelling) {
				t.Errorf("%s leaked the seed as %s: %q", path, encoding, rendered)
			}
		}
		// Redaction that also removes the identity is not usable: a caller has to be able to
		// tell which request was logged.
		if !strings.Contains(rendered, "rq12") {
			t.Errorf("%s dropped the short code: %q", path, rendered)
		}
	}
}

func TestTheAccessLinkIsWithheldWhileTheCollectLinkIsNot(t *testing.T) {
	// The access link IS the seed, in the one form somebody will paste into a chat window.
	// The collect link is not a secret and is kept, because withholding it would make the
	// redacted forms useless for the case they exist for.
	seed := []byte("0123456789abcdef0123456789abcdef")
	created := SecureRequest{
		ShortCode:   "rq12",
		Seed:        seed,
		CollectLink: "https://crs.sh/r/rq12",
		AccessLink:  "https://crs.sh/r/rq12#1" + base64.RawURLEncoding.EncodeToString(seed),
	}
	asJSON, err := json.Marshal(created)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(asJSON), "https://crs.sh/r/rq12\"") {
		t.Fatalf("the collect link was withheld too: %s", asJSON)
	}
	if strings.Contains(string(asJSON), "#1") {
		t.Fatalf("the access link fragment survived: %s", asJSON)
	}
}

func TestCreateRequestAlwaysSendsAnIdempotencyKey(t *testing.T) {
	// Required by the API, and a duplicate collect link is worse than a duplicate share
	// because a person can fill it in.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt},
	}); err != nil {
		t.Fatal(err)
	}
	if rec.requests[0].Headers.Get("Idempotency-Key") == "" {
		t.Fatal("no Idempotency-Key was sent")
	}
}

func TestASuppliedIdempotencyKeySurvivesACreate(t *testing.T) {
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt}, IdempotencyKey: "deploy-42",
	}); err != nil {
		t.Fatal(err)
	}
	if got := rec.requests[0].Headers.Get("Idempotency-Key"); got != "deploy-42" {
		t.Fatalf("Idempotency-Key = %q", got)
	}
}

func TestAFieldlessRequestIsRefusedBeforeAnyRequest(t *testing.T) {
	// The API refuses it now, but the failure it protects against was invisible: a 201, a
	// live short code, and "Unable to Load Request" for the human who opened the link.
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)

	for _, params := range []CreateRequestParams{
		{Title: "t"},
		{Title: "t", Fields: []RequestField{}},
		{Title: "t", Fields: []RequestField{{Type: "text"}}},
	} {
		_, err := client.CreateRequest(context.Background(), params)
		if !errors.Is(err, ErrInvalidField) {
			t.Errorf("got %v, want ErrInvalidField", err)
		}
	}
	if len(rec.requests) != 0 {
		t.Fatal("something was sent")
	}
}

func TestAPromptWithNoTypeLeavesTheDefaultToTheAPI(t *testing.T) {
	// The API documents the default as "text". Restating it on the wire is how a client
	// starts drifting from a default it does not own.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{{Item: "Password"}},
	}); err != nil {
		t.Fatal(err)
	}
	if body := rec.requests[0].Body; !strings.Contains(body, `"fields":[{"item":"Password"}]`) {
		t.Fatalf("fields = %s", body)
	}
}

func TestTheOptionalMetadataReachesTheBody(t *testing.T) {
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title:            "t",
		Fields:           []RequestField{testPrompt},
		Description:      "for the new starter",
		ExpiredAt:        "2026-12-01T00:00:00Z",
		MaxSubmission:    3,
		AccessCountsLeft: 5,
		RequiresLogin:    true,
		RequiresMfa:      true,
		RestrictedDomain: []string{"example.com"},
		IPWhitelist:      []string{"203.0.113.4"},
		OrganizationID:   "org_1",
	}); err != nil {
		t.Fatal(err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(rec.requests[0].Body), &parsed); err != nil {
		t.Fatal(err)
	}
	for _, member := range []string{
		"description", "expired_at", "max_submission", "access_counts_left",
		"requires_login", "requires_mfa", "restricted_domain", "ip_whitelist",
		"organization_id",
	} {
		if _, ok := parsed[member]; !ok {
			t.Errorf("%s is missing from %v", member, parsed)
		}
	}
	// An omitted option must not appear at all — a zero this client invented is a policy
	// this client does not get to set.
	if _, ok := parsed["passcode"]; ok {
		t.Error("passcode was sent though none was set")
	}
}

// -- reads ----------------------------------------------------------------------------

func TestListRequestsCarriesItsPagingFigures(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"requests": []any{map[string]any{
			"short_code": "rq12", "expired_at": "2026-10-02T00:00:00Z", "public_key": "BASE64URL",
		}},
		"pagination": map[string]any{"page": 1, "limit": 2, "total": 5, "total_pages": 3},
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListRequests(context.Background(), 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 5 || page.TotalPages != 3 || !page.HasMore() {
		t.Fatalf("page = %+v", page)
	}
	if page.Requests[0].ShortCode != "rq12" || page.Requests[0].PublicKey != "BASE64URL" {
		t.Fatalf("requests = %+v", page.Requests)
	}
	if page.Requests[0].ExpiredAt == nil {
		t.Fatal("expired_at was dropped")
	}
}

func TestTheRequestListDefaultsToTwentyFive(t *testing.T) {
	// 25 is the API's own default for every v1 list, and the specification's "default: 10" is
	// wrong. Locked down here because correcting it TOWARDS the specification would silently
	// change what every caller's first page contains, and after a tag it could not be undone.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"requests": []any{},
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListRequests(context.Background(), 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Limit != 25 || page.Page != 1 {
		t.Fatalf("page = %+v", page)
	}
	if !strings.Contains(rec.requests[0].URL, "limit=25") {
		t.Fatalf("URL = %s", rec.requests[0].URL)
	}
}

func TestIterateRequestsDoesNotStopOnAShortMiddlePage(t *testing.T) {
	// The bug in every hand-rolled version of this loop, and the reason requests get the
	// same iterator shares do rather than a fresh one.
	page := func(codes []string, number int) stubResponse {
		rows := make([]any, 0, len(codes))
		for _, code := range codes {
			rows = append(rows, map[string]any{"short_code": code})
		}
		return stubResponse{status: 200, body: map[string]any{
			"requests":   rows,
			"pagination": map[string]any{"page": number, "limit": 2, "total": 5, "total_pages": 3},
		}}
	}
	rec := &recorder{responses: []stubResponse{
		page([]string{"a1", "a2"}, 1), page([]string{"b1"}, 2), page([]string{"c1", "c2"}, 3),
	}}
	client := newTestClient(t, rec, testCredential)

	var seen []string
	if err := client.IterateRequests(context.Background(), 2, func(r RequestSummary) error {
		seen = append(seen, r.ShortCode)
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

func TestIterateRequestsRefusesAServerThatEchoesAConstantPage(t *testing.T) {
	// Terminating on the server's echo instead of the counter this loop controls is how the
	// walk either stops on page one or never stops at all.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"requests":   []any{map[string]any{"short_code": "a1"}, map[string]any{"short_code": "a2"}},
		"pagination": map[string]any{"page": 1, "limit": 2, "total": 99, "total_pages": 50},
	}}}}
	client := newTestClient(t, rec, testCredential)

	err := client.IterateRequests(context.Background(), 2, func(RequestSummary) error { return nil })
	if !errors.Is(err, ErrAPI) || !strings.Contains(err.Error(), "cannot") {
		t.Fatalf("got %v", err)
	}
}

func TestGetRequestReturnsThePublicKeyItStored(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"short_code": "rq12", "expired_at": nil, "public_key": "BASE64URL",
	}}}}
	client := newTestClient(t, rec, testCredential)

	summary, err := client.GetRequest(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if summary.PublicKey != "BASE64URL" || summary.ExpiredAt != nil {
		t.Fatalf("summary = %+v", summary)
	}
	if !strings.HasSuffix(rec.requests[0].URL, "/requests/rq12") {
		t.Fatalf("URL = %s", rec.requests[0].URL)
	}
}

func TestAMissingRequestReportsNotFound(t *testing.T) {
	// A request on another account reports identically, so a credential cannot be used to
	// discover what other accounts hold.
	rec := &recorder{responses: []stubResponse{{status: 404, body: map[string]any{"message": "no such request"}}}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.GetRequest(context.Background(), "rq12"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestDeleteRequestReportsWhichOfTheTwoStepsItTook(t *testing.T) {
	// Two-step by design: the first call expires and preserves the submissions received so
	// far, the second deletes. A caller who assumes one call removes the request leaves the
	// row in place, so the outcome is returned rather than inferred.
	rec := &recorder{responses: []stubResponse{
		{status: 200, body: map[string]any{"short_code": "rq12", "outcome": "expired"}},
		{status: 200, body: map[string]any{"short_code": "rq12", "outcome": "deleted"}},
	}}
	client := newTestClient(t, rec, testCredential)

	first, err := client.DeleteRequest(context.Background(), "rq12")
	if err != nil || first.Outcome != "expired" || first.ShortCode != "rq12" {
		t.Fatalf("first = %+v, %v", first, err)
	}
	second, err := client.DeleteRequest(context.Background(), "rq12")
	if err != nil || second.Outcome != "deleted" || second.ShortCode != "rq12" {
		t.Fatalf("second = %+v, %v", second, err)
	}
	if rec.requests[0].Method != http.MethodDelete ||
		!strings.HasSuffix(rec.requests[0].URL, "/requests/rq12") {
		t.Fatalf("request = %+v", rec.requests[0])
	}
}

// -- submissions ----------------------------------------------------------------------

// sealTo seals a field array to a request's public key the way a submitter's browser does:
// the section 4 wrap layout, standard padded base64.
func sealTo(t *testing.T, seed []byte, fields []Field) string {
	t.Helper()
	keypair, err := KeypairFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := WrapToPublicKey(payload, keypair.PublicKeyRaw)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestASubmissionComesBackSealedAndOpensWithTheSeed(t *testing.T) {
	// The whole round trip: we hand over something we cannot open, to the party who can.
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	answered := []Field{{Key: "Staging database password", Value: "s3cr3t", Type: "password"}}
	blob := sealTo(t, seed, answered)

	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": []any{map[string]any{
			"short_code":      "sb12",
			"created_at":      "2026-09-02T10:00:00Z",
			"data":            blob,
			"encryption_type": encryptionType,
		}},
		"count": 1,
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListSubmissions(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Submissions) != 1 || page.Count != 1 {
		t.Fatalf("page = %+v", page)
	}
	submission := page.Submissions[0]
	if submission.Data != blob {
		t.Fatal("the blob was not handed back verbatim")
	}
	if submission.ShortCode != "sb12" || submission.CreatedAt == "" ||
		submission.EncryptionType != encryptionType {
		t.Fatalf("submission = %+v", submission)
	}

	fields, err := submission.Decrypt(seed)
	if err != nil {
		t.Fatal(err)
	}
	if len(fields) != 1 || !fields[0].Equal(answered[0]) {
		t.Fatalf("decrypted %+v", fields)
	}

	// The package-level entry point must agree with the method, blob first.
	direct, err := DecryptSubmission(blob, seed)
	if err != nil || !direct[0].Equal(answered[0]) {
		t.Fatalf("DecryptSubmission = %+v, %v", direct, err)
	}
	if !strings.HasSuffix(rec.requests[0].URL, "/requests/rq12/submissions") {
		t.Fatalf("URL = %s", rec.requests[0].URL)
	}
}

func TestListingASubmissionDoesNotDecryptIt(t *testing.T) {
	// Listing is deliberately not decryption: a caller counting submissions should never
	// hold the plaintext, and the seed belongs at the call site that actually needs it.
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	blob := sealTo(t, seed, []Field{{Key: "Password", Value: "correct horse", Type: "password"}})

	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": []any{map[string]any{"short_code": "sb12", "data": blob}},
		"count":       1,
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListSubmissions(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%+v", page), "correct horse") {
		t.Fatal("the page carried plaintext")
	}
}

func TestASubmissionSealedToAnotherRequestDoesNotOpen(t *testing.T) {
	// A wrong seed and an altered blob are indistinguishable, deliberately: both are
	// ErrWireFormat, and telling them apart would be an oracle.
	mine, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	blob := sealTo(t, theirs, []Field{{Key: "k", Value: "v", Type: "text"}})

	if _, err := DecryptSubmission(blob, mine); !errors.Is(err, ErrWireFormat) {
		t.Fatalf("got %v, want ErrWireFormat", err)
	}
}

func TestReEncodingASubmissionBlobBreaksIt(t *testing.T) {
	// The encoding trap from the other side. The blob is PADDED STANDARD base64 while the
	// request's public key is unpadded base64url; a caller who normalises one to the other
	// gets a blob that will not open, with nothing to say why.
	seed, err := NewSeed()
	if err != nil {
		t.Fatal(err)
	}
	blob := sealTo(t, seed, []Field{{Key: "k", Value: "v", Type: "text"}})

	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatalf("the blob was not standard base64: %v", err)
	}
	if _, err := DecryptSubmission(base64.RawURLEncoding.EncodeToString(raw), seed); err == nil {
		t.Fatal("a base64url-re-encoded blob opened, so the decoders are interchangeable")
	}
}

func TestWithheldLegacySubmissionsAreCounted(t *testing.T) {
	// The API refuses to return submissions it could read itself. Surfacing the count is
	// what stops that looking like an empty page to somebody reconciling against their
	// dashboard.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions":                      []any{},
		"count":                            0,
		"skipped_not_end_to_end_encrypted": 3,
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListSubmissions(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if page.SkippedNotEndToEndEncrypted != 3 {
		t.Fatalf("skipped = %d", page.SkippedNotEndToEndEncrypted)
	}
	if len(page.Submissions) != 0 || page.Count != 0 {
		t.Fatalf("page = %+v", page)
	}
}

func TestSubmissionsAreOneFetchWithNoPagingParameters(t *testing.T) {
	// The endpoint reads neither a page nor a limit and answers with every row plus a count.
	// A client that paged it would be handed the same rows again — for a request with enough
	// submissions, forever — so ListSubmissions takes no paging arguments, sends none, and
	// IterateSubmissions makes exactly one call.
	rows := []any{
		map[string]any{"short_code": "sb1", "data": "AQ=="},
		map[string]any{"short_code": "sb2", "data": "AQ=="},
	}
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": rows, "count": 2,
	}}}}
	client := newTestClient(t, rec, testCredential)

	var seen []string
	if err := client.IterateSubmissions(context.Background(), "rq12", func(s Submission) error {
		seen = append(seen, s.ShortCode)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "sb1,sb2" {
		t.Fatalf("walked %v", seen)
	}
	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests for an answer that was already complete", len(rec.requests))
	}
	if url := rec.requests[0].URL; strings.Contains(url, "limit") || strings.Contains(url, "page") {
		t.Fatalf("paging parameters were sent to an endpoint that ignores them: %s", url)
	}
}

// A pagination block, if one ever appeared, is not walked either: the response shape this
// endpoint actually serves is the whole set, and guessing that a full page means another one
// exists is the defect this replaced.
func TestASubmissionsAnswerIsNeverAskedForTwice(t *testing.T) {
	rows := make([]any, 0, 100)
	for i := 0; i < 100; i++ {
		rows = append(rows, map[string]any{"short_code": fmt.Sprintf("sb%d", i), "data": "AQ=="})
	}
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": rows, "count": 100,
	}}}}
	client := newTestClient(t, rec, testCredential)

	count := 0
	if err := client.IterateSubmissions(context.Background(), "rq12", func(Submission) error {
		count++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count != 100 {
		t.Fatalf("yielded %d rows", count)
	}
	if len(rec.requests) != 1 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
}

func TestAnErrorFromTheCallbackStopsTheWalk(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": []any{
			map[string]any{"short_code": "sb1", "data": "AQ=="},
			map[string]any{"short_code": "sb2", "data": "AQ=="},
		},
		"count": 2,
	}}}}
	client := newTestClient(t, rec, testCredential)

	stop := errors.New("enough")
	count := 0
	err := client.IterateSubmissions(context.Background(), "rq12", func(Submission) error {
		count++
		return stop
	})
	if !errors.Is(err, stop) || count != 1 {
		t.Fatalf("err = %v after %d calls", err, count)
	}
}

// -- the escape hatch -------------------------------------------------------------------

// Do is the supported way to reach an endpoint this SDK does not wrap, so the mandatory
// header has to be its problem rather than each caller's. The API requires an
// Idempotency-Key on a create and a caller who has to remember it forgets it exactly once —
// on the write that mints a second copy of a secret.

func TestAPostPutOrPatchIsGivenAnIdempotencyKeyItWasNotGiven(t *testing.T) {
	// Those three and not "every non-GET": see idempotencyKeyedMethods. They are the calls
	// where repeating a request differs from making it once.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
		client := newTestClient(t, rec, testCredential)

		if _, err := client.Do(context.Background(), Call{Method: method, Path: "/anything"}); err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		if rec.requests[0].Headers.Get("Idempotency-Key") == "" {
			t.Errorf("%s went out with no Idempotency-Key", method)
		}
	}

	// Lower-cased by a caller reaching Do directly. The allow-list must not turn a valid
	// method into an unkeyed one on a spelling.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.Do(context.Background(), Call{Method: "post", Path: "/anything"}); err != nil {
		t.Fatal(err)
	}
	if rec.requests[0].Headers.Get("Idempotency-Key") == "" {
		t.Error("a lower-cased post went out with no Idempotency-Key")
	}
}

func TestADeleteIsGivenNoIdempotencyKeyOfOurOwn(t *testing.T) {
	// A compatibility assertion as much as a design one, and the reason the allow-list is
	// three methods rather than "not a GET".
	//
	// ExpireShare is a DELETE /shares/{code} that shipped at 0.1.4 sending no such header.
	// Generating one would change the bytes of an already-published call — which a minor
	// release does not get to do — and buy nothing: the API consults the header on a create,
	// so a key on a delete is inert, and a repeated delete is idempotent by construction.
	rec := &recorder{responses: []stubResponse{
		{status: 200, body: map[string]any{}},
		{status: 200, body: map[string]any{}},
		{status: 200, body: map[string]any{}},
	}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.Do(context.Background(), Call{
		Method: http.MethodDelete, Path: "/anything",
	}); err != nil {
		t.Fatal(err)
	}
	if err := client.ExpireShare(context.Background(), "ab12"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.DeleteRequest(context.Background(), "rq12"); err != nil {
		t.Fatal(err)
	}

	for _, sent := range rec.requests {
		if got := sent.Headers.Get("Idempotency-Key"); got != "" {
			t.Errorf("%s %s carried Idempotency-Key %q", sent.Method, sent.URL, got)
		}
	}
	if len(rec.requests) != 3 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
}

func TestASuppliedIdempotencyKeyIsForwardedOnADelete(t *testing.T) {
	// The allow-list governs only what the SDK adds by itself. A caller who has a key they
	// can reproduce is doing the thing the header is for, on whatever method they chose, and
	// dropping it would be a different kind of silent wire edit.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.Do(context.Background(), Call{
		Method:  http.MethodDelete,
		Path:    "/anything",
		Headers: map[string]string{"idempotency-key": "cleanup-42"},
	}); err != nil {
		t.Fatal(err)
	}
	if got := rec.requests[0].Headers.Get("Idempotency-Key"); got != "cleanup-42" {
		t.Fatalf("Idempotency-Key = %q", got)
	}
	if got := rec.requests[0].Headers.Values("Idempotency-Key"); len(got) != 1 {
		t.Fatalf("sent %d values: %v", len(got), got)
	}
}

func TestASuppliedIdempotencyKeyIsNeverOverwritten(t *testing.T) {
	// A caller sets their own because they can reproduce it on retry — which is the only
	// thing the header protects. Replacing it with one of ours would defeat the reason they
	// set it, and the header casing they used must not decide whether that happens.
	for _, name := range []string{"Idempotency-Key", "idempotency-key", "IDEMPOTENCY-KEY"} {
		rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
		client := newTestClient(t, rec, testCredential)

		_, err := client.Do(context.Background(), Call{
			Method:  http.MethodPost,
			Path:    "/anything",
			Body:    map[string]any{"a": 1},
			Headers: map[string]string{name: "deploy-42"},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := rec.requests[0].Headers.Get("Idempotency-Key"); got != "deploy-42" {
			t.Errorf("supplied as %q, sent as %q", name, got)
		}
		if got := rec.requests[0].Headers.Values("Idempotency-Key"); len(got) != 1 {
			t.Errorf("supplied as %q, sent %d values: %v", name, len(got), got)
		}
	}
}

func TestAGetCallIsGivenNoIdempotencyKey(t *testing.T) {
	// A read cannot create anything twice, and a key on a GET is noise that invites somebody
	// to conclude the header means something it does not.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.Do(context.Background(), Call{Path: "/shares"}); err != nil {
		t.Fatal(err)
	}
	if rec.requests[0].Method != http.MethodGet {
		t.Fatalf("an empty Method should mean GET, got %s", rec.requests[0].Method)
	}
	if got := rec.requests[0].Headers.Get("Idempotency-Key"); got != "" {
		t.Fatalf("a GET carried Idempotency-Key %q", got)
	}
}

func TestTheGeneratedIdempotencyKeyIsIdenticalOnARetry(t *testing.T) {
	// The one property that makes generating a key safe at all. A fresh key on the second
	// attempt is precisely how one secret becomes two, so it is generated once per call
	// rather than once per attempt.
	rec := &recorder{failures: 1, responses: []stubResponse{{status: 201, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.Do(context.Background(), Call{
		Method: http.MethodPost, Path: "/anything", Body: map[string]any{"a": 1},
	}); err != nil {
		t.Fatal(err)
	}
	if len(rec.requests) != 2 {
		t.Fatalf("made %d requests", len(rec.requests))
	}
	first := rec.requests[0].Headers.Get("Idempotency-Key")
	if first == "" || first != rec.requests[1].Headers.Get("Idempotency-Key") {
		t.Fatalf("the retry used a different key: %q then %q",
			first, rec.requests[1].Headers.Get("Idempotency-Key"))
	}
	if rec.requests[0].Body != rec.requests[1].Body {
		t.Fatal("the retried body differed from the first")
	}
}

func TestDoDoesNotMutateTheCallersHeaderMap(t *testing.T) {
	// The map belongs to the caller. A second call made with the same map must not inherit
	// the first call's key — which would be a body change under a used key, refused as an
	// idempotency conflict, blamed on the API.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{}}}}
	client := newTestClient(t, rec, testCredential)

	headers := map[string]string{"X-Trace": "abc"}
	if _, err := client.Do(context.Background(), Call{
		Method: http.MethodPost, Path: "/anything", Headers: headers,
	}); err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("the caller's map gained members: %v", headers)
	}
}

func TestTheCustodySecretIsRefusedInACallerSuppliedHeader(t *testing.T) {
	// Do lets a caller set any header, and the realistic accident is the whole three-part
	// credential pasted into one. The assertion is about the property, not about which line
	// assembled the value.
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)

	_, err := client.Do(context.Background(), Call{
		Method:  http.MethodPost,
		Path:    "/anything",
		Headers: map[string]string{"Authorization": "Bearer " + testCredential},
	})
	if !errors.Is(err, ErrCustodySecretTransmitted) {
		t.Fatalf("got %v, want ErrCustodySecretTransmitted", err)
	}
	if len(rec.requests) != 0 {
		t.Fatal("the request was sent anyway")
	}
}

func TestDoSurfacesTheSameErrorsTheTypedMethodsDo(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 403, body: map[string]any{"error_code": 61}}}}
	client := newTestClient(t, rec, testCredential)
	_, err := client.Do(context.Background(), Call{Path: "/stats"})
	if !errors.Is(err, ErrQuotaExceeded) || !errors.Is(err, ErrAPI) {
		t.Fatalf("got %v", err)
	}
}

// -- the params on the way IN -----------------------------------------------------------

// Compile-time, so a receiver changed from a value to a pointer fails the build rather than
// one assertion inside one test. A pointer method is absent from the VALUE's method set,
// which is the direction that matters here: params are passed by value.
var (
	_ fmt.Stringer   = CreateRequestParams{}
	_ fmt.GoStringer = CreateRequestParams{}
	_ json.Marshaler = CreateRequestParams{}
	_ slog.LogValuer = CreateRequestParams{}
)

func TestCreateRequestParamsWithholdItsSeedFromEverySerializationPath(t *testing.T) {
	// The same four leaks SecureRequest was taught to close, in a wider window: the seed is
	// in the PARAMS before the call that returns it, so a caller logging what they are about
	// to send leaked exactly what logging the result no longer does. %+v printed the bytes,
	// %#v printed them as []uint8{...}, json.Marshal emitted them as base64 and an slog JSON
	// handler wrote the same into the line.
	//
	// The passcode is asserted with the seed: it IS transmitted, but it is a value the caller
	// chose and may have reused elsewhere, and a struct dump is how that becomes a permanent
	// record.
	//
	// Pointer AND dereferenced value AND a copy, because a method on a pointer receiver is
	// absent from a copy's method set — which is exactly how a redaction test passes while a
	// %+v of the value a caller actually holds prints the secret.
	seed := []byte("0123456789abcdef0123456789abcdef")
	const passcode = "correct-horse-battery-staple"
	params := CreateRequestParams{
		Title:    "Onboarding credentials",
		Fields:   []RequestField{testPrompt},
		Passcode: passcode,
		Seed:     seed,
	}
	pointer := &params

	var logged strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logged, nil))
	logger.Info("creating a request", "params", params)
	logger.Info("creating a request", "params", pointer)

	asJSON, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	asJSONPointer, err := json.Marshal(pointer)
	if err != nil {
		t.Fatal(err)
	}
	inASlice, err := json.Marshal([]CreateRequestParams{params})
	if err != nil {
		t.Fatal(err)
	}
	inAMap, err := json.Marshal(map[string]CreateRequestParams{"params": params})
	if err != nil {
		t.Fatal(err)
	}

	renderings := map[string]string{
		"%v on the value":          fmt.Sprintf("%v", params),
		"%v on the pointer":        fmt.Sprintf("%v", pointer),
		"%+v on the value":         fmt.Sprintf("%+v", params),
		"%+v on the pointer":       fmt.Sprintf("%+v", pointer),
		"%+v on a dereference":     fmt.Sprintf("%+v", *pointer),
		"%#v on the value":         fmt.Sprintf("%#v", params),
		"%#v on the pointer":       fmt.Sprintf("%#v", pointer),
		"%s on the value":          fmt.Sprintf("%s", params),
		"%s on the pointer":        fmt.Sprintf("%s", pointer),
		"a slice of them":          fmt.Sprintf("%v", []CreateRequestParams{params}),
		"json.Marshal(value)":      string(asJSON),
		"json.Marshal(pointer)":    string(asJSONPointer),
		"json.Marshal(slice)":      string(inASlice),
		"json.Marshal(map)":        string(inAMap),
		"slog with a JSON handler": logged.String(),
	}
	spellings := map[string]string{
		"raw bytes":                string(seed),
		"decimal bytes":            fmt.Sprintf("%d", seed),
		"hex":                      hex.EncodeToString(seed),
		"padded standard base64":   base64.StdEncoding.EncodeToString(seed),
		"unpadded standard base64": strings.TrimRight(base64.StdEncoding.EncodeToString(seed), "="),
		"base64url":                base64.RawURLEncoding.EncodeToString(seed),
		"the passcode":             passcode,
	}

	for path, rendered := range renderings {
		for encoding, spelling := range spellings {
			if strings.Contains(rendered, spelling) {
				t.Errorf("%s leaked the seed as %s: %q", path, encoding, rendered)
			}
		}
		// Redaction that also removes the identity is not usable: whoever is reading the log
		// has to be able to tell which create this was.
		if !strings.Contains(rendered, "Onboarding credentials") {
			t.Errorf("%s dropped the title: %q", path, rendered)
		}
	}
}

func TestTheParamsSayWhetherASecretWasSuppliedWithoutSayingWhat(t *testing.T) {
	// Whether a seed or a passcode was set is usually the thing being debugged, and a
	// redaction that hides even that sends somebody back to printing the struct by hand.
	empty := CreateRequestParams{Title: "t", Fields: []RequestField{testPrompt}}
	if got := empty.String(); !strings.Contains(got, "seed [unset]") ||
		!strings.Contains(got, "passcode [unset]") {
		t.Fatalf("unset params render as %q", got)
	}
	full := CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt},
		Passcode: "p", Seed: make([]byte, SeedLength),
	}
	if got := full.String(); !strings.Contains(got, "seed [redacted]") ||
		!strings.Contains(got, "passcode [redacted]") {
		t.Fatalf("populated params render as %q", got)
	}
}

func TestTheRedactedParamsAreNotWhatGoesOnTheWire(t *testing.T) {
	// MarshalJSON is deliberately lossy, so the create body must not be built from it. The
	// body is assembled member by member inside CreateRequest against the names the API
	// reads — this asserts that those two are not the same path, because a lossy marshaller
	// wired into the wire would send "[redacted]" as a passcode and lose the public key.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "")}}
	client := newTestClient(t, rec, testCredential)

	if _, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title:    "Onboarding credentials",
		Fields:   []RequestField{testPrompt},
		Passcode: "correct-horse-battery-staple",
	}); err != nil {
		t.Fatal(err)
	}
	body := rec.requests[0].Body
	if strings.Contains(body, "[redacted]") || strings.Contains(body, "[unset]") {
		t.Fatalf("a redaction placeholder reached the wire: %s", body)
	}
	if !strings.Contains(body, `"passcode":"correct-horse-battery-staple"`) {
		t.Fatalf("the passcode did not reach the API, which gates the link on it: %s", body)
	}
}

// -- paging figures ---------------------------------------------------------------------

func TestRequestPageHasMoreClimbsThreeRungs(t *testing.T) {
	// One rung — TotalPages alone — reported "no more" on a full page whenever the server
	// omitted the pagination block, which is how a walk returns a fraction of the account and
	// says nothing. The other three SDKs climb all three rungs; a divergence here would look
	// like one language truncating and not the others.
	rows := func(n int) []RequestSummary { return make([]RequestSummary, n) }

	for name, tc := range map[string]struct {
		page RequestPage
		want bool
	}{
		"total_pages says more":       {RequestPage{Requests: rows(25), Page: 1, Limit: 25, TotalPages: 3}, true},
		"total_pages says this is it": {RequestPage{Requests: rows(25), Page: 1, Limit: 25, TotalPages: 1}, false},
		"total_pages beats a total that disagrees": {
			RequestPage{Requests: rows(25), Page: 1, Limit: 25, Total: 900, TotalPages: 1}, false,
		},
		"total says more":               {RequestPage{Requests: rows(25), Page: 1, Limit: 25, Total: 60}, true},
		"total says this is it":         {RequestPage{Requests: rows(25), Page: 1, Limit: 25, Total: 25}, false},
		"a full page with no figures":   {RequestPage{Requests: rows(25), Page: 1, Limit: 25}, true},
		"a short page with no figures":  {RequestPage{Requests: rows(7), Page: 2, Limit: 25}, false},
		"an empty page with no figures": {RequestPage{Page: 2, Limit: 25}, false},
		// The guard that stops the fallback becoming an endless run of requests: a server
		// echoing limit: 0 leaves nothing to measure progress against, so no rung may claim
		// there is more.
		"a zero limit with a total":      {RequestPage{Requests: rows(25), Page: 1, Limit: 0, Total: 60}, false},
		"a zero limit with no figures":   {RequestPage{Requests: rows(25), Page: 1, Limit: 0}, false},
		"a zero limit and an empty page": {RequestPage{Page: 1, Limit: 0}, false},
	} {
		if got := tc.page.HasMore(); got != tc.want {
			t.Errorf("%s: HasMore() = %v, want %v", name, got, tc.want)
		}
	}
}

func TestListRequestsAnswersHasMoreFromAFullPageWithNoPaginationBlock(t *testing.T) {
	// The rung that matters in practice: the block is absent and the page is full.
	rows := make([]any, 25)
	for i := range rows {
		rows[i] = map[string]any{"short_code": fmt.Sprintf("rq%02d", i)}
	}
	rec := &recorder{responses: []stubResponse{
		{status: 200, body: map[string]any{"requests": rows}},
	}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListRequests(context.Background(), 25, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !page.HasMore() {
		t.Fatalf("a full page with no figures reported no successor: %+v", page)
	}
}

// -- the API's echo ---------------------------------------------------------------------

func TestThePublicKeyOnACreateIsTheApisEcho(t *testing.T) {
	// The member documents itself as the value to quote when reconciling against GetRequest.
	// Filled in from our own keypair it could only ever agree with itself, so a caller
	// performing that comparison was comparing a local value with a local value.
	rec := &recorder{responses: []stubResponse{requestStub("rq12", "ECHOED-BY-THE-API")}}
	client := newTestClient(t, rec, testCredential)

	created, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{testPrompt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.PublicKey != "ECHOED-BY-THE-API" {
		t.Fatalf("PublicKey = %q, want the API's echo", created.PublicKey)
	}
}

func TestAnAbsentOrBlankPublicKeyEchoFallsBackToTheDerivedOne(t *testing.T) {
	// Falling back to the local derivation rather than to an empty string: an empty public
	// key is not information, and this member is never empty on a successful create.
	for name, body := range map[string]map[string]any{
		"absent":       {"short_code": "rq12"},
		"blank":        {"short_code": "rq12", "public_key": ""},
		"not a string": {"short_code": "rq12", "public_key": 42},
	} {
		rec := &recorder{responses: []stubResponse{{status: 201, body: body}}}
		client := newTestClient(t, rec, testCredential)

		created, err := client.CreateRequest(context.Background(), CreateRequestParams{
			Title: "t", Fields: []RequestField{testPrompt},
		})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		keypair, err := KeypairFromSeed(created.Seed)
		if err != nil {
			t.Fatal(err)
		}
		if created.PublicKey != keypair.PublicKeyB64URL {
			t.Errorf("%s: PublicKey = %q, want the derived %q",
				name, created.PublicKey, keypair.PublicKeyB64URL)
		}
	}
}

// -- the submission count ---------------------------------------------------------------

func TestTheSubmissionCountIsNotBackfilledFromTheSliceLength(t *testing.T) {
	// Count is the API's own figure, and its only use is being compared against
	// len(Submissions). Defaulting it to that length made the two agree by construction and
	// destroyed the disagreement it exists to expose. Node, Python and Rust leave it absent;
	// Go has no absent int, so it stays zero.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": []any{
			map[string]any{"short_code": "sb01", "data": "AAAA"},
			map[string]any{"short_code": "sb02", "data": "BBBB"},
		},
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListSubmissions(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Submissions) != 2 {
		t.Fatalf("got %d submissions", len(page.Submissions))
	}
	if page.Count != 0 {
		t.Fatalf("Count = %d, want 0 for a response that carried none", page.Count)
	}
}

func TestACountThatDisagreesWithTheRowsSurvives(t *testing.T) {
	// The case the member is for: the server says five and sends two. Reconciling that here
	// would hide it.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"submissions": []any{
			map[string]any{"short_code": "sb01", "data": "AAAA"},
			map[string]any{"short_code": "sb02", "data": "BBBB"},
		},
		"count": 5,
	}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.ListSubmissions(context.Background(), "rq12")
	if err != nil {
		t.Fatal(err)
	}
	if page.Count != 5 || len(page.Submissions) != 2 {
		t.Fatalf("Count = %d over %d rows", page.Count, len(page.Submissions))
	}
}
