package credenshare

// The secure-request surface: a keyless collect link, the submissions to it, and the seed
// that is the only way to read them.
//
// A share hands a secret OUT. A request collects one IN, from a person who needs no account
// and no key of their own — their browser encrypts to the public key you published with the
// request. Every submitter seals to that same public key and none of them can read another's,
// and neither can we, because the private half is a 32-byte seed that never leaves this
// process.
//
// That asymmetry is why CreateRequest returns the seed rather than storing it anywhere: it is
// not a convenience, it is the entire read capability. Lose it and the submissions are
// unrecoverable by everyone, us included.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// A RequestField is one prompt on the collect form.
//
// Item is the VISIBLE PROMPT — "Staging database password" — and it is the request-side
// counterpart of a share Field's Key, with the same trap behind it: "label", "name" and
// "title" are silently ignored, and a request whose prompts are empty renders as a form of
// unnamed boxes to whoever you sent it to, with nothing erroring anywhere.
//
// Type is how the prompt renders for the submitter, from the same vocabulary as a share
// field's — see FieldTypes. Left empty it is omitted from the request body and the API
// applies its documented default of "text"; that default belongs to the API, so this SDK
// does not restate it on the wire and cannot drift from it.
//
// Two members and no more, unlike a share Field, which preserves members it does not know
// about. That is deliberate rather than an omission: the API unmarshals a request's prompts
// into exactly item and type, so an extra member is accepted without error and NOT STORED. A
// share's extras survive because they travel inside the ciphertext; a request's prompts are
// plaintext metadata and do not.
type RequestField struct {
	Item string `json:"item"`
	Type string `json:"type,omitempty"`
}

// validateRequestFields checks the prompts before anything is sent.
//
// Unexported, while the share-side ValidateFields is public: a request's prompts are checked
// on the one path that sends them, so exporting this would add a name to a v1 surface that
// nothing outside this package needs and that could not be removed afterwards. The check
// itself exists because the failure is invisible from the API — a request created with no
// fields at all returns a 201 and a live short code, and the human who opens the link gets
// "Unable to Load Request". The API refuses an empty array now, so this mostly saves a round
// trip; what it adds is the reason, which a validation-failed response does not carry.
func validateRequestFields(fields []RequestField) error {
	if len(fields) == 0 {
		return fmt.Errorf(
			"%w: a request needs at least one field; a request with none renders as "+
				"'Unable to Load Request' for whoever you send it to",
			ErrInvalidField,
		)
	}
	for i, field := range fields {
		if field.Item == "" {
			return fmt.Errorf(
				"%w: field %d has no 'item' (its visible prompt)", ErrInvalidField, i,
			)
		}
	}
	return nil
}

// A SecureRequest is a created secure request, and the only place its seed exists.
//
// Every representation Go reaches for reflexively is redacted — String, GoString, MarshalJSON
// and slog.LogValue — because each of them is a route by which the seed would otherwise
// become a permanent plaintext record. See the methods below.
type SecureRequest struct {
	ShortCode string

	// Seed is the 32-byte private seed for this request's keypair. KEEP IT. It is the only
	// way to read the submissions — it was generated on this machine, never transmitted, and
	// we cannot reissue it. Pass it to Submission.Decrypt or DecryptSubmission later, or
	// feed it back through CreateRequestParams.Seed to reconstruct the same keypair.
	Seed []byte

	// PublicKey is the public half that was registered, unpadded base64url — the API's own
	// echo of it, falling back to the value derived here when the response carried none.
	//
	// The echo rather than the local derivation, matching Node and Rust. This member exists to
	// be quoted when reconciling against GetRequest, which returns the API's copy, and a field
	// populated from our own keypair on both sides of that comparison can only ever agree with
	// itself — it would document a check it does not perform.
	//
	// A blank echo counts as no echo and takes the fallback: an empty string is not a public
	// key, and the same idiom governs RequestDeletion.ShortCode. So this is never empty on a
	// successful create, whatever the API sent.
	PublicKey string

	// CollectLink is the keyless link you hand to a human.
	//
	// Safe to paste into a ticket: holding it lets somebody SUBMIT and never read. It
	// carries no fragment, which is what makes that true.
	CollectLink string

	// AccessLink is your own link, with the seed in the fragment.
	//
	// TREAT IT AS THE SECRET ITSELF. Anyone holding it can read every submission to this
	// request, on any device, with nothing stored — and we cannot rebuild it, because the
	// seed was never ours. Withheld from every representation this type prints.
	AccessLink string

	ExpiredAt *string
}

// String withholds the seed and the access link. The seed is the read capability for every
// submission this request will ever collect, and %v on a struct is how a secret usually
// reaches a log.
//
// A VALUE receiver, not a pointer one: a pointer method is absent from a dereferenced or
// copied value's method set, so a %+v of *created would print the seed bytes in full while
// the same verb on the pointer looked clean.
func (r SecureRequest) String() string {
	return fmt.Sprintf("<SecureRequest %s (seed and access link withheld)>", r.ShortCode)
}

// GoString covers %#v, which would otherwise print the seed bytes.
func (r SecureRequest) GoString() string { return r.String() }

// MarshalJSON withholds the seed and the access link.
//
// encoding/json is the path a struct most often leaves a process by — a response body, a
// state file, a queue message — and an exported []byte member serializes as base64 with
// nothing about the call site looking wrong. The collect link is kept, because it is not a
// secret.
//
// Deliberately lossy: the result does not unmarshal back into a usable SecureRequest, which
// is the point. Store the seed yourself, on purpose, somewhere you chose.
func (r SecureRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ShortCode   string  `json:"short_code"`
		PublicKey   string  `json:"public_key"`
		CollectLink string  `json:"collect_link"`
		AccessLink  string  `json:"access_link"`
		ExpiredAt   *string `json:"expired_at"`
		Seed        string  `json:"seed"`
	}{
		ShortCode:   r.ShortCode,
		PublicKey:   r.PublicKey,
		CollectLink: r.CollectLink,
		AccessLink:  "[redacted - contains the seed]",
		ExpiredAt:   r.ExpiredAt,
		Seed:        "[redacted]",
	})
}

// LogValue withholds the seed and the access link from log/slog.
//
// slog reaches neither String nor MarshalJSON: a JSON handler handed this struct resolves the
// []byte itself and writes the seed into the log line. This is the interface that stops it,
// and it is why passing a SecureRequest to slog.Info is safe rather than merely discouraged.
func (r SecureRequest) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("short_code", r.ShortCode),
		slog.String("public_key", r.PublicKey),
		slog.String("collect_link", r.CollectLink),
		slog.String("access_link", "[redacted - contains the seed]"),
		slog.String("seed", "[redacted]"),
	)
}

// A RequestSummary is metadata for a request. Never a submission, and never a private key.
//
// PublicKey is returned by the API and kept here deliberately, unlike anything key-shaped on
// a share: it is the PUBLIC half, you supplied it, and getting it back is how you confirm
// what was stored. It is empty on a request created before the API required one, and on the
// stub body the API returns for a request that has since been deleted.
type RequestSummary struct {
	ShortCode string  `json:"short_code"`
	ExpiredAt *string `json:"expired_at"`
	PublicKey string  `json:"public_key"`
}

// A RequestDeletion is what DeleteRequest did.
//
// Two members, matching the API's own answer, so a caller is told which of the two steps ran
// rather than left to infer it from a status code.
type RequestDeletion struct {
	// ShortCode is the request that was acted on. Populated from the API's echo, falling
	// back to the short code that was asked for.
	ShortCode string

	// Outcome is "expired", "deleted", or EMPTY when the API answered without one.
	//
	// Empty is NOT coerced to "expired". The deployed API always sends an outcome, so an
	// empty value means something changed on the other side — and inventing the
	// safer-sounding of the two would tell a caller their submissions were preserved on a
	// call that may have removed them.
	Outcome string
}

// A RequestPage is one page of requests with the paging figures attached.
//
// Same shape as SharePage, and for the same reason: a bare slice leaves a caller guessing
// whether more exists, and a caller who has to guess stops at the first short page.
type RequestPage struct {
	Requests   []RequestSummary
	Page       int
	Limit      int
	Total      int
	TotalPages int
}

// HasMore reports whether another page exists.
//
// Three rungs, in descending order of how much the server told us, which is the ladder Node,
// Python and Rust all climb. Answering false on a FULL page because the paging figures were
// absent is what makes a walk stop after page one and hand back a fraction of the account as
// though it were all of it — the truncation is silent, which is why the fallback exists rather
// than a bare comparison against TotalPages.
//
// The Limit > 0 guard on the lower two rungs is load-bearing rather than defensive. A server
// echoing "limit": 0 is believed by intFrom, and 0 < Total is true on every page including
// empty ones, which converts the truncation into an unbounded run of requests — strictly worse
// than the bug the fallback fixes. With no limit to measure progress against, no rung may
// claim there is more.
func (p *RequestPage) HasMore() bool {
	if p.TotalPages > 0 {
		return p.Page < p.TotalPages
	}
	if p.Total > 0 {
		// Widened before multiplying: Page * Limit overflows an int32 on a 32-bit build long
		// before a real account would, and an overflow here reports "no more" and truncates.
		return p.Limit > 0 && int64(p.Page)*int64(p.Limit) < int64(p.Total)
	}
	// Nothing to go on but the page itself: a full page probably has a successor, and a short
	// one ends the walk.
	return p.Limit > 0 && len(p.Requests) >= p.Limit
}

// A Submission is one sealed answer to a request.
//
// Data is the sealed blob exactly as the API served it: STANDARD base64, padded, per section
// 4 of the wire specification. This is the one place on /v1 that returns content, and it is
// the metadata-only rule working rather than an exception to it — the blob is sealed to the
// request's public key, so handing it over discloses nothing to us.
//
// Nothing here decrypts on its own. Call Decrypt with the seed you kept.
//
// There is no expiry member. The submissions endpoint sends short_code, created_at, data and
// encryption_type and nothing else, and a member that is always nil reads as a broken field
// rather than as an absent one.
type Submission struct {
	ShortCode string
	CreatedAt string
	Data      string

	// EncryptionType is what the API says the blob is. The submissions endpoint returns only
	// client-encrypted rows, and reports the ones it withheld — see
	// SubmissionPage.SkippedNotEndToEndEncrypted.
	EncryptionType string
}

// Decrypt opens this submission with the seed from CreateRequest.
//
// Equivalent to DecryptSubmission(s.Data, seed); it exists so that the blob and the seed
// cannot be transposed at the call site.
func (s Submission) Decrypt(seed []byte) ([]Field, error) {
	return DecryptSubmission(s.Data, seed)
}

// A SubmissionPage is every submission to a request.
//
// The whole set rather than one page of it: the endpoint answers with all of them and a
// count, and reads neither a page nor a limit. So there are no paging figures here to expose
// and nothing to walk — ListSubmissions is one call, and IterateSubmissions is one call with
// a callback. A client that paged this endpoint would be handed the same rows again.
type SubmissionPage struct {
	Submissions []Submission

	// Count is the API's own count member: the number of rows it RETURNED. Kept alongside
	// len(Submissions) rather than replacing it, so that the two disagreeing is visible
	// instead of being silently reconciled here.
	//
	// NOT defaulted to len(Submissions) when the API omits the member. It stays zero, which is
	// as close as this language gets to the absent value Node, Python and Rust expose here.
	// Filling it in from the slice would make the two figures agree by construction and
	// destroy the only signal that the server's own count and its payload disagree — which is
	// the single thing this member is for. The deployed endpoint always sends a count, so zero
	// beside a non-empty slice means "the server did not say", not "no submissions".
	Count int

	// SkippedNotEndToEndEncrypted counts submissions the API withheld because they are not
	// client-encrypted — legacy rows the server can actually read, which it will not return
	// over a bearer-authenticated API.
	//
	// Surfaced rather than swallowed: a caller reconciling against their dashboard would
	// otherwise see fewer submissions than it shows and have no way to learn why.
	SkippedNotEndToEndEncrypted int
}

// CreateRequestParams describes a secure request to create.
type CreateRequestParams struct {
	Title  string
	Fields []RequestField

	Description string

	// Passcode gates the collect link, and unlike a share's passcode IT IS SENT.
	//
	// Not an oversight and not a weaker choice: a share's passcode is mixed into the content
	// key's derivation, so it must stay on your machine and the server gets a one-way
	// verifier instead. A submission is sealed to this request's public key, and nothing
	// about that encryption depends on the passcode — it is a server-side gate on who may
	// open the form, so the server needs it. Do not reuse a value that protects anything
	// else.
	Passcode string

	// ExpiredAt defaults to 30 DAYS from now when empty, applied by the API rather than
	// here. Omitting it does not create a collect link that stays open forever.
	ExpiredAt string

	// MaxSubmission caps how many people may submit.
	MaxSubmission int
	// AccessCountsLeft caps how many times the link may be opened.
	AccessCountsLeft int

	RequiresLogin    bool
	RequiresMfa      bool
	RestrictedDomain []string
	IPWhitelist      []string

	// OrganizationID scopes the request to a team the credential acts in.
	OrganizationID string

	// IdempotencyKey is generated per call unless you set it. Setting your own does NOT make
	// a second call a no-op in general — but here, unlike a share, it can be: this body is
	// deterministic given the same params and the same Seed, so a replay of the identical
	// body returns the original short code. Change anything, including letting the seed be
	// generated afresh, and the API refuses with ErrIdempotencyConflict. That is the header
	// working, not failing.
	//
	// Do not derive it from Seed. This is a HEADER, so it leaves the machine — the boundary
	// assertion in CreateRequest checks this value as well as the body, and refuses.
	IdempotencyKey string

	// Seed creates the request under a keypair you already hold, rather than a fresh one.
	//
	// The case this exists for is the custody-derived runner: take the seed from
	// CustodyKeypair and hand it in, and an ephemeral container reconstructs the same read
	// capability with no local state. Must be SeedLength bytes.
	//
	// Leave it nil and a fresh seed is generated here, returned in SecureRequest.Seed, and
	// never transmitted.
	Seed []byte
}

// String withholds the seed and the passcode.
//
// The same four accessors SecureRequest carries, for the same reason and against a worse
// window: the seed is in THIS struct before the call that returns it, so the params on the way
// in leak precisely what the result on the way out was taught not to. A %+v of them printed
// the 32 bytes, %#v printed them as []uint8{...}, json.Marshal emitted them as base64 and an
// slog JSON handler wrote the same into the log line.
//
// The passcode goes with the seed. It is sent — see the member — but it is a value the caller
// chose and may have reused, and a struct dump is how a chosen secret becomes a permanent
// record. Everything that is not a secret is kept, because a redaction that removes the
// identity is not usable by whoever is reading the log.
//
// A VALUE receiver, not a pointer one: a pointer method is absent from a dereferenced or
// copied value's method set, and these params are passed BY VALUE to CreateRequest, so a
// pointer receiver would leave the overwhelmingly common rendering — %+v of the copy — printing
// the seed while the same verb on a pointer looked clean.
func (p CreateRequestParams) String() string {
	return fmt.Sprintf(
		"<CreateRequestParams %q, %d field(s), seed %s, passcode %s>",
		p.Title, len(p.Fields), secretState(len(p.Seed) > 0), secretState(p.Passcode != ""),
	)
}

// GoString covers %#v, which would otherwise print the seed as []uint8{...}.
func (p CreateRequestParams) GoString() string { return p.String() }

// MarshalJSON withholds the seed and the passcode.
//
// NOT the create body. The body CreateRequest sends is assembled member by member inside the
// method, against the names the API actually reads, so this being deliberately lossy cannot
// affect the wire — and the boundary assertion scans that serialized body, not this.
//
// What it protects is the other direction: params written to a state file, an audit record or
// a queue message, where an exported []byte serializes as base64 with nothing at the call site
// looking wrong.
func (p CreateRequestParams) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Title            string         `json:"title"`
		Fields           []RequestField `json:"fields"`
		Description      string         `json:"description,omitempty"`
		ExpiredAt        string         `json:"expired_at,omitempty"`
		MaxSubmission    int            `json:"max_submission,omitempty"`
		AccessCountsLeft int            `json:"access_counts_left,omitempty"`
		RequiresLogin    bool           `json:"requires_login,omitempty"`
		RequiresMfa      bool           `json:"requires_mfa,omitempty"`
		RestrictedDomain []string       `json:"restricted_domain,omitempty"`
		IPWhitelist      []string       `json:"ip_whitelist,omitempty"`
		OrganizationID   string         `json:"organization_id,omitempty"`
		IdempotencyKey   string         `json:"idempotency_key,omitempty"`
		Passcode         string         `json:"passcode"`
		Seed             string         `json:"seed"`
	}{
		Title:            p.Title,
		Fields:           p.Fields,
		Description:      p.Description,
		ExpiredAt:        p.ExpiredAt,
		MaxSubmission:    p.MaxSubmission,
		AccessCountsLeft: p.AccessCountsLeft,
		RequiresLogin:    p.RequiresLogin,
		RequiresMfa:      p.RequiresMfa,
		RestrictedDomain: p.RestrictedDomain,
		IPWhitelist:      p.IPWhitelist,
		OrganizationID:   p.OrganizationID,
		IdempotencyKey:   p.IdempotencyKey,
		Passcode:         secretState(p.Passcode != ""),
		Seed:             secretState(len(p.Seed) > 0),
	})
}

// LogValue withholds the seed and the passcode from log/slog.
//
// slog reaches neither String nor MarshalJSON on its own terms: a JSON handler handed this
// struct resolves the []byte itself and writes the seed into the log line. This is the
// interface that stops it, and it is why passing params to slog.Info is safe rather than
// merely discouraged.
func (p CreateRequestParams) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("title", p.Title),
		slog.Int("fields", len(p.Fields)),
		slog.String("expired_at", p.ExpiredAt),
		slog.Int("max_submission", p.MaxSubmission),
		slog.Int("access_counts_left", p.AccessCountsLeft),
		slog.String("organization_id", p.OrganizationID),
		slog.String("idempotency_key", p.IdempotencyKey),
		slog.String("passcode", secretState(p.Passcode != "")),
		slog.String("seed", secretState(len(p.Seed) > 0)),
	)
}

// CreateRequest creates a secure request — a keyless collect link — and RETURNS ITS SEED.
//
// The keypair is generated on this machine. Only the public half is sent; the 32-byte seed
// comes back in SecureRequest.Seed and goes nowhere else, which is the whole point of the
// feature: submissions are sealed to a key we never held, so we can hand them to you and
// cannot read them ourselves. Keep the seed or the submissions are unrecoverable — by you, by
// us, by anybody. There is no reissue.
//
// The seed never being transmitted is ASSERTED at the boundary rather than trusted to the
// field list below: the serialized body and the outgoing Idempotency-Key are both scanned for
// it before anything is sent, so a later edit that routes it into either one fails here with
// ErrRequestSeedTransmitted instead of in production.
//
// The public key travels as UNPADDED BASE64URL while a submission's sealed blob comes back as
// PADDED STANDARD base64. Two encodings on one feature, which is worth knowing if you ever
// hand either to a decoder of your own; this SDK feeds each to the right one.
func (c *Client) CreateRequest(
	ctx context.Context, params CreateRequestParams,
) (*SecureRequest, error) {
	if err := validateRequestFields(params.Fields); err != nil {
		return nil, err
	}

	seed := params.Seed
	if seed == nil {
		var err error
		if seed, err = NewSeed(); err != nil {
			return nil, err
		}
	}
	// Checked before the keypair is derived, so a wrong-length seed is a typed SDK error a
	// caller can branch on rather than whatever the crypto primitive underneath raises.
	if len(seed) != SeedLength {
		return nil, fmt.Errorf(
			"%w: a request seed is %d bytes; this one is %d",
			ErrMalformedKey, SeedLength, len(seed),
		)
	}
	keypair, err := KeypairFromSeed(seed)
	if err != nil {
		return nil, err
	}

	body := map[string]any{
		"title":      params.Title,
		"fields":     params.Fields,
		"public_key": keypair.PublicKeyB64URL,
	}
	if params.Description != "" {
		body["description"] = params.Description
	}
	if params.Passcode != "" {
		body["passcode"] = params.Passcode
	}
	if params.ExpiredAt != "" {
		body["expired_at"] = params.ExpiredAt
	}
	if params.MaxSubmission > 0 {
		body["max_submission"] = params.MaxSubmission
	}
	if params.AccessCountsLeft > 0 {
		body["access_counts_left"] = params.AccessCountsLeft
	}
	if params.RequiresLogin {
		body["requires_login"] = true
	}
	if params.RequiresMfa {
		body["requires_mfa"] = true
	}
	if len(params.RestrictedDomain) > 0 {
		body["restricted_domain"] = params.RestrictedDomain
	}
	if len(params.IPWhitelist) > 0 {
		body["ip_whitelist"] = params.IPWhitelist
	}
	if params.OrganizationID != "" {
		body["organization_id"] = params.OrganizationID
	}

	idempotencyKey := params.IdempotencyKey
	if idempotencyKey == "" {
		// Required by the API, not optional — and a duplicate collect link is worse than a
		// duplicate share, because a person can fill it in. Set at this call site rather
		// than left to the generic layer's backstop, so the requirement is stated where the
		// create is.
		if idempotencyKey, err = randomToken(); err != nil {
			return nil, err
		}
	}

	// Belt and braces, at the boundary, in the manner of the custody assertion in request().
	//
	// Checked against the SERIALIZED body — the same bytes request() will marshal — so a
	// seed smuggled in through a title, a description or a prompt is caught too, not only
	// one added to the body map above. And checked against the Idempotency-Key, because that
	// value is caller-supplied and travels as a HEADER: a scan of the body alone would watch
	// the front door while a deterministic-key recipe carried the seed out of the back.
	if err := assertSeedStaysHere(seed, body, idempotencyKey); err != nil {
		return nil, err
	}

	data, err := c.request(ctx, http.MethodPost, "/requests", body, nil,
		map[string]string{idempotencyHeader: idempotencyKey})
	if err != nil {
		return nil, err
	}

	created := &SecureRequest{Seed: seed}
	// The API's echo, falling back to what was derived here rather than to an empty string:
	// this member's use is being compared against the API's copy, and one filled in locally on
	// both sides of that comparison checks nothing. Node and Rust read it the same way.
	if echoed, ok := data["public_key"].(string); ok && echoed != "" {
		created.PublicKey = echoed
	} else {
		created.PublicKey = keypair.PublicKeyB64URL
	}
	if code, ok := data["short_code"].(string); ok {
		created.ShortCode = code
	}
	if expired, ok := data["expired_at"].(string); ok {
		created.ExpiredAt = &expired
	}
	created.CollectLink = c.CollectLinkFor(created.ShortCode)
	if created.AccessLink, err = c.AccessLinkFor(created.ShortCode, seed); err != nil {
		return nil, err
	}
	return created, nil
}

// seedRenderings is every encoding a 32-byte seed could plausibly be written in, for the
// boundary assertion.
//
// Three rather than one because the point is to catch a seed that reached the wire through a
// route nobody anticipated, and whoever hand-rolled that route reached for whichever encoder
// was nearest. The standard-base64 spelling is UNPADDED on purpose: unpadded is a prefix of
// the padded form, so one entry matches both, while the reverse does not.
func seedRenderings(seed []byte) []string {
	return []string{
		b64url.EncodeToString(seed),
		strings.TrimRight(b64.EncodeToString(seed), "="),
		hex.EncodeToString(seed),
	}
}

// assertSeedStaysHere refuses to send anything carrying the seed.
func assertSeedStaysHere(seed []byte, body map[string]any, idempotencyKey string) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("serialising the request: %w", err)
	}
	serialized := string(payload)
	for _, rendering := range seedRenderings(seed) {
		if strings.Contains(serialized, rendering) {
			return fmt.Errorf(
				"%w: the submissions to a request whose seed reached the server are not "+
					"zero-knowledge, so expire it and create a new one rather than retrying",
				ErrRequestSeedTransmitted,
			)
		}
		if strings.Contains(idempotencyKey, rendering) {
			return fmt.Errorf(
				"%w in the %s header: an idempotency key derived from the seed carries it "+
					"out of the process; use a value that is not the secret",
				ErrRequestSeedTransmitted, idempotencyHeader,
			)
		}
	}
	return nil
}

// ListRequests returns one page of the account's requests, newest first. Metadata only.
//
// The limit defaults to 25, which is the API's own default for every v1 list, and the server
// caps it at 100.
func (c *Client) ListRequests(ctx context.Context, limit, page int) (*RequestPage, error) {
	if limit <= 0 {
		limit = 25
	}
	if page <= 0 {
		page = 1
	}

	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("page", strconv.Itoa(page))

	data, err := c.request(ctx, http.MethodGet, "/requests", nil, query, nil)
	if err != nil {
		return nil, err
	}

	result := &RequestPage{Page: page, Limit: limit}
	if rows, ok := data["requests"].([]any); ok {
		for _, row := range rows {
			entry, ok := row.(map[string]any)
			if !ok {
				continue
			}
			result.Requests = append(result.Requests, requestSummaryFrom(entry))
		}
	}
	if pagination, ok := data["pagination"].(map[string]any); ok {
		result.Page = intFrom(pagination["page"], page)
		result.Limit = intFrom(pagination["limit"], limit)
		result.Total = intFrom(pagination["total"], 0)
		result.TotalPages = intFrom(pagination["total_pages"], 0)
	}
	return result, nil
}

// maxPages bounds a walk whose termination the server's own figures failed to establish.
//
// A hard stop rather than a loop that trusts the response: an endpoint echoing a full page
// forever would otherwise turn one call into an unbounded run of requests, and the caller
// would see rate limits rather than the bug. Not applied to IterateShares, which is already
// published without it.
const maxPages = 100_000

// IterateRequests walks every page, calling fn for each request.
//
// The same loop as IterateShares, including the two things a hand-rolled version gets wrong:
// it does not stop on a page shorter than the limit, which the server may return in the
// middle of a result set, and it terminates on the counter it controls rather than on the
// page number the server echoes. Returning a non-nil error from fn stops the walk.
func (c *Client) IterateRequests(ctx context.Context, limit int, fn func(RequestSummary) error) error {
	if limit <= 0 {
		limit = 100
	}
	for page := 1; ; page++ {
		if page > maxPages {
			return fmt.Errorf(
				"%w: the request list did not terminate within %d pages, so it is not being "+
					"walked any further", ErrAPI, maxPages,
			)
		}
		batch, err := c.ListRequests(ctx, limit, page)
		if err != nil {
			return err
		}
		if batch.Page != page {
			return fmt.Errorf(
				"%w: asked for page %d and the API answered with page %d, so paging cannot "+
					"be trusted to terminate", ErrAPI, page, batch.Page,
			)
		}
		for _, request := range batch.Requests {
			if err := fn(request); err != nil {
				return err
			}
		}
		if batch.TotalPages > 0 {
			if page >= batch.TotalPages {
				return nil
			}
			continue
		}
		// No TotalPages: keep going while pages come back full, and stop on the first short
		// one. Treating an absent count as "no more" silently returns a fraction of the
		// account as though it were all of it.
		if len(batch.Requests) < limit {
			return nil
		}
	}
}

// GetRequest returns one request's metadata.
//
// It does not return submissions, and a request belonging to another account reports exactly
// as one that does not exist. A request the account has since deleted answers with its short
// code and nothing else rather than a 404, so an empty PublicKey and a nil ExpiredAt here
// mean "gone", not "never had one".
func (c *Client) GetRequest(ctx context.Context, shortCode string) (*RequestSummary, error) {
	data, err := c.request(
		ctx, http.MethodGet, "/requests/"+url.PathEscape(shortCode), nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}
	summary := requestSummaryFrom(data)
	if summary.ShortCode == "" {
		summary.ShortCode = shortCode
	}
	return &summary, nil
}

// DeleteRequest expires a request, and deletes it on the second call.
//
// Two-step by design, and the returned RequestDeletion says which happened rather than
// leaving you to infer it: "expired" on an active request — new submissions stop, the ones
// already received are preserved — and "deleted" when called again on an already-expired one,
// which removes it outright.
//
// So a single call does NOT remove the request, and a caller who treats one call as a delete
// leaves the row in place. Deletion is irreversible: afterwards the sealed submissions are
// gone, and they were never readable by us in the first place.
//
// A request belonging to another account reports as not-found, so this cannot be used to
// probe for requests elsewhere.
//
// RequestDeletion.Outcome is empty when the API answered without one, and is deliberately not
// defaulted to either value. DO NOT retry on an unclear result, here or on
// ErrDeliveryUnknown: the second call deletes what the first one expired, and the submissions
// go with it. Reconcile with GetRequest instead — a request that is still listed with an
// expiry was expired, not deleted.
func (c *Client) DeleteRequest(ctx context.Context, shortCode string) (*RequestDeletion, error) {
	data, err := c.request(
		ctx, http.MethodDelete, "/requests/"+url.PathEscape(shortCode), nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}
	deletion := &RequestDeletion{ShortCode: shortCode}
	if code, ok := data["short_code"].(string); ok && code != "" {
		deletion.ShortCode = code
	}
	deletion.Outcome, _ = data["outcome"].(string)
	return deletion, nil
}

// ListSubmissions returns the sealed submissions to a request — all of them, in one call.
//
// Not paged, because the endpoint is not: it reads neither a page nor a limit and answers
// with every client-encrypted row plus a count. Asking for a second page would hand back the
// same rows, so this method does not offer one and IterateSubmissions does not walk.
//
// The blobs come back sealed. Open them with Submission.Decrypt and the seed from
// CreateRequest — this method deliberately does not, so that a caller who only wants counts
// or timestamps never holds the plaintext, and so the seed appears at the call site that
// actually needs it.
func (c *Client) ListSubmissions(
	ctx context.Context, shortCode string,
) (*SubmissionPage, error) {
	data, err := c.request(
		ctx, http.MethodGet, "/requests/"+url.PathEscape(shortCode)+"/submissions",
		nil, nil, nil,
	)
	if err != nil {
		return nil, err
	}

	result := &SubmissionPage{}
	if rows, ok := data["submissions"].([]any); ok {
		for _, row := range rows {
			entry, ok := row.(map[string]any)
			if !ok {
				continue
			}
			submission := Submission{}
			if code, ok := entry["short_code"].(string); ok {
				submission.ShortCode = code
			}
			if created, ok := entry["created_at"].(string); ok {
				submission.CreatedAt = created
			}
			if blob, ok := entry["data"].(string); ok {
				submission.Data = blob
			}
			if kind, ok := entry["encryption_type"].(string); ok {
				submission.EncryptionType = kind
			}
			result.Submissions = append(result.Submissions, submission)
		}
	}
	// Zero rather than len(Submissions) when the API omits the member. The fallback made the
	// two figures agree by construction, which is exactly the disagreement Count exists to
	// expose; Node, Python and Rust all leave it absent for that reason. See the member's doc.
	result.Count = intFrom(data["count"], 0)
	result.SkippedNotEndToEndEncrypted = intFrom(data["skipped_not_end_to_end_encrypted"], 0)
	return result, nil
}

// IterateSubmissions calls fn for each submission to a request. Returning a non-nil error
// from fn stops it.
//
// ONE HTTP call, unlike IterateShares and IterateRequests, and the difference is
// load-bearing rather than an inconsistency. Those two walk a paged endpoint. This one
// answers with every submission at once and ignores the page entirely, so a walk that asked
// for a second page would be handed the first one again — for a request with enough
// submissions, forever. The callback shape is kept so that reading submissions looks like
// reading shares at the call site.
func (c *Client) IterateSubmissions(
	ctx context.Context, shortCode string, fn func(Submission) error,
) error {
	batch, err := c.ListSubmissions(ctx, shortCode)
	if err != nil {
		return err
	}
	for _, submission := range batch.Submissions {
		if err := fn(submission); err != nil {
			return err
		}
	}
	return nil
}

// DecryptSubmission opens a sealed submission blob with the request's seed.
//
// The blob comes FIRST and the seed second, matching Submission.Decrypt and the other three
// SDKs: the thing being opened, then the key that opens it.
//
// The blob is unwrapped per section 4 of the wire specification, and the plaintext inside is
// the same field array a share carries (section 2.2.1) — so what comes back is a []Field,
// with unknown members preserved.
//
// The blob is PADDED STANDARD base64: the encoding the API serves it in, and NOT the unpadded
// base64url the request's public key travels as. Hand it over verbatim; re-encoding it
// produces a blob that will not open. UnwrapWithSeed is the primitive underneath, for a
// payload that is not a field array.
//
// A blob sealed to a different request's key and one that was altered are indistinguishable
// here, deliberately: both surface as ErrWireFormat.
func DecryptSubmission(data string, seed []byte) ([]Field, error) {
	payload, err := UnwrapWithSeed(data, seed)
	if err != nil {
		return nil, err
	}
	var fields []Field
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, fmt.Errorf("%w: the unwrapped submission is not a field array", ErrWireFormat)
	}
	return fields, nil
}

func requestSummaryFrom(entry map[string]any) RequestSummary {
	summary := RequestSummary{}
	if code, ok := entry["short_code"].(string); ok {
		summary.ShortCode = code
	}
	if expired, ok := entry["expired_at"].(string); ok {
		summary.ExpiredAt = &expired
	}
	if key, ok := entry["public_key"].(string); ok {
		summary.PublicKey = key
	}
	return summary
}
