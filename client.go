package credenshare

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultBaseURL is the production API.
	DefaultBaseURL = "https://api.credenshare.io/v1"
	// DefaultLinkOrigin is where recipient links live.
	DefaultLinkOrigin = "https://crs.sh"

	// encryptionType is the only accepted value. Plaintext creates are refused by the server,
	// and this client has no way to express one.
	encryptionType = "e2ee-aes256-gcm"

	// quotaExceededCode distinguishes a spent allowance from other 403s: waiting does not
	// help and the remedy is a plan change, not a retry.
	quotaExceededCode = 61

	// idempotencyConflictCode marks an Idempotency-Key replayed with a different body.
	idempotencyConflictCode = 105

	credentialPrefix = "crs_sk_live_"

	// DefaultMaxRetries applies to network failures only, never to an HTTP status: a 5xx may
	// have committed and this client cannot tell. A create is safe to retry because the
	// Idempotency-Key and the body are both identical on the second attempt — which is the
	// entire reason the header is mandatory.
	DefaultMaxRetries = 2

	// DefaultTimeout applies to each attempt when Options.Timeout is zero and no HTTPClient
	// with a timeout of its own is supplied.
	DefaultTimeout = 30 * time.Second
)

// A Credential is a parsed API credential: crs_sk_live_<keyId>.<authSecret>[.<custodySecret>].
//
// The custody secret is held here but is NEVER placed in a request. It is a separate secret
// precisely so the server cannot reconstruct the custody private key — deriving it from the
// auth secret, which is transmitted on every call, would mean the server *could* decrypt. Not
// that it would; that it could.
type Credential struct {
	KeyID string

	authSecret    string
	custodySecret string
}

// ParseCredential parses the two- or three-part form.
func ParseCredential(raw string) (*Credential, error) {
	text := strings.TrimSpace(raw)
	if !strings.HasPrefix(text, credentialPrefix) {
		return nil, fmt.Errorf(
			"%w: a credential starts with %q; this does not look like one",
			ErrCredentialFormat, credentialPrefix,
		)
	}
	parts := strings.Split(text, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return nil, fmt.Errorf(
			"%w: a credential is '%s<keyId>.<authSecret>' with an optional '.<custodySecret>'; "+
				"this has %d part(s)",
			ErrCredentialFormat, credentialPrefix, len(parts),
		)
	}
	for _, part := range parts {
		if part == "" {
			return nil, fmt.Errorf("%w: a credential part is empty", ErrCredentialFormat)
		}
	}

	credential := &Credential{
		KeyID:      strings.TrimPrefix(parts[0], credentialPrefix),
		authSecret: parts[1],
	}
	if len(parts) == 3 {
		credential.custodySecret = parts[2]
	}
	return credential, nil
}

// HasCustody reports whether a custody secret is present.
func (c *Credential) HasCustody() bool { return c.custodySecret != "" }

// bearer is the two-part value sent in the Authorization header.
//
// Assembled from the parts rather than by trimming the original string, so a third part cannot
// survive a formatting mistake and reach the wire.
func (c *Credential) bearer() string {
	return credentialPrefix + c.KeyID + "." + c.authSecret
}

// CustodyPublicKey returns the base64url custody public key to register for account custody.
//
// Only the public half leaves this machine. Any machine holding the credential derives the
// same keypair, so ephemeral runners need no local state.
func (c *Credential) CustodyPublicKey() (string, error) {
	if c.custodySecret == "" {
		return "", fmt.Errorf(
			"%w: this credential has no custody secret, so no custody keypair exists",
			ErrCredentialFormat,
		)
	}
	pair, err := CustodyKeypair(c.custodySecret)
	if err != nil {
		return "", err
	}
	return pair.PublicKeyB64URL, nil
}

// WrapToCustody wraps a payload to this credential's own custody public key.
//
// Done here rather than by handing the secret out: the custody secret is the one value the
// server deliberately cannot hold, and an accessor is all it takes for it to reach a log.
func (c *Credential) WrapToCustody(payload []byte) (string, error) {
	if c.custodySecret == "" {
		return "", fmt.Errorf(
			"%w: custody needs a three-part credential "+
				"'crs_sk_live_<keyId>.<authSecret>.<custodySecret>'; this one has two parts, "+
				"so there is no custody key to wrap to",
			ErrCredentialFormat,
		)
	}
	pair, err := CustodyKeypair(c.custodySecret)
	if err != nil {
		return "", err
	}
	return WrapToPublicKey(payload, pair.PublicKeyRaw)
}

// String never renders the secrets. A credential in a log line is a credential that has to be
// rotated, and %v on a struct is how that usually happens.
func (c *Credential) String() string {
	custody := "no custody"
	if c.HasCustody() {
		custody = "with custody"
	}
	return fmt.Sprintf("<Credential %s (%s)>", c.KeyID, custody)
}

// GoString covers %#v, which would otherwise print the unexported fields.
func (c *Credential) GoString() string { return c.String() }

// A Share is a created share, and the only place its link exists.
type Share struct {
	ShortCode string
	// Link is the full recipient link, INCLUDING the key fragment. Treat it as the secret
	// itself: anyone holding it can read the content, and CredenShare cannot.
	Link string
	// ContentKey is kept if you need to build your own link or decrypt later.
	ContentKey []byte
	ExpiredAt  *string
	Custody    string
}

// String withholds the link. The link carries the key, so printing a Share should not spill it
// into a log.
func (s *Share) String() string {
	return fmt.Sprintf("<Share %s (link withheld)>", s.ShortCode)
}

// A ShareSummary is metadata for a share. Never content, and never a key.
//
// Deliberately thin, because the API is: /v1 returns the short code and the expiry and nothing
// else. There is no Title here even though you supply one on create — the server does not
// return it, and a field that is always empty reads as broken rather than absent.
type ShareSummary struct {
	ShortCode string  `json:"short_code"`
	ExpiredAt *string `json:"expired_at"`
}

// A SharePage is one page of shares with the paging figures attached.
//
// A bare slice would leave a caller guessing whether more exists, and a caller who has to guess
// guesses wrong — usually by stopping at the first short page.
type SharePage struct {
	Shares     []ShareSummary
	Page       int
	Limit      int
	Total      int
	TotalPages int
}

// HasMore reports whether another page exists.
func (p *SharePage) HasMore() bool { return p.TotalPages > 0 && p.Page < p.TotalPages }

// CreateParams describes a share to create.
type CreateParams struct {
	Title            string
	Fields           []Field
	Description      string
	Passcode         string
	ExpiredAt        string
	AccessCountsLeft int
	TimedView        int

	// Custody also wraps the content key to the custody public key derived from the
	// credential's third part, so the share is readable from the dashboard later.
	//
	// Without it an API-created share is custody "none": the link is the only way back to the
	// content, and losing it loses the secret. CustodyPublicKey exists to register that key,
	// but until this flag there was no way to actually use it from a create.
	Custody bool

	// ItemKeyWrap is a wrap computed by the caller. Mutually exclusive with Custody.
	ItemKeyWrap string

	OrganizationID string

	// IdempotencyKey is generated per call unless you set it. Setting your own does NOT make
	// a second call a no-op: encryption is randomised per call, so the body differs and the
	// API refuses with ErrIdempotencyConflict. That is the header working, not failing. What
	// it protects is a network retry, which this client performs itself.
	IdempotencyKey string

	// ContentKey creates a share under a key you already hold — a link you handed out before
	// the create, or a fixed key in a test. It does not make the request body reproducible.
	ContentKey []byte
}

// Options configure a Client.
type Options struct {
	BaseURL    string
	LinkOrigin string
	HTTPClient *http.Client

	// MaxRetries is a pointer so that 0 means "do not retry" rather than "unset".
	// With a plain int the two are indistinguishable, and a caller who deliberately
	// disabled retries silently got the default of 2 instead.
	MaxRetries *int

	// Timeout applies to each attempt. Zero uses DefaultTimeout. Ignored when HTTPClient
	// is supplied with a timeout of its own.
	Timeout time.Duration
}

// Retries returns a pointer to n, for setting Options.MaxRetries inline.
//
// Options.MaxRetries is a pointer so that Retries(0) genuinely disables retries; a plain
// int cannot distinguish "zero" from "not set".
func Retries(n int) *int { return &n }

// A Client talks to the /v1 API.
type Client struct {
	Credential *Credential

	baseURL    string
	linkOrigin string
	httpClient *http.Client
	maxRetries int
}

// New builds a client from a credential.
//
// The credential accepts the two- or three-part form. With the three-part one, the custody
// secret stays on this machine — it derives a keypair locally and is never transmitted.
func New(credential string, opts *Options) (*Client, error) {
	parsed, err := ParseCredential(credential)
	if err != nil {
		return nil, err
	}
	if opts == nil {
		opts = &Options{}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	client := &Client{
		Credential: parsed,
		baseURL:    strings.TrimRight(orDefault(opts.BaseURL, DefaultBaseURL), "/"),
		linkOrigin: strings.TrimRight(orDefault(opts.LinkOrigin, DefaultLinkOrigin), "/"),
		httpClient: opts.HTTPClient,
		maxRetries: DefaultMaxRetries,
	}
	if opts.MaxRetries != nil {
		client.maxRetries = *opts.MaxRetries
		if client.maxRetries < 0 {
			client.maxRetries = 0
		}
	}
	if client.httpClient == nil {
		client.httpClient = &http.Client{Timeout: timeout}
	} else if client.httpClient.Timeout == 0 && opts.Timeout > 0 {
		// A supplied client with no timeout of its own would otherwise wait forever,
		// which is the one thing a caller passing Timeout was trying to prevent.
		client.httpClient.Timeout = timeout
	}
	return client, nil
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// LinkFor assembles a recipient link.
//
// The key lives in the fragment, which browsers never send to a server. That is what makes the
// link readable by its holder and opaque to us.
func (c *Client) LinkFor(shortCode string, contentKey []byte) (string, error) {
	fragment, err := EncodeFragment(contentKey)
	if err != nil {
		return "", err
	}
	return c.linkOrigin + "/" + shortCode + "#" + fragment, nil
}

// ReadLink is not implemented, on purpose.
//
// The recipient path is deliberately absent from the API, because bearer auth skips the
// proof-of-work and captcha gates that protect it, and exposing it to a credential would be an
// enumeration bypass. Open the link in a browser, or use DecryptContent on a blob you hold.
func (c *Client) ReadLink(_ string) ([]Field, error) {
	return nil, fmt.Errorf(
		"%w: the recipient read path is not exposed over the API by design; open the link "+
			"in a browser, or use DecryptContent on a blob you already have",
		ErrNotSupported,
	)
}

// CreateShare encrypts fields locally and creates a share.
//
// Each field's Key is the visible label — not "label", "name" or "title", which the recipient
// view ignores silently and would render blank.
func (c *Client) CreateShare(ctx context.Context, params CreateParams) (*Share, error) {
	contentKey := params.ContentKey
	if contentKey == nil {
		var err error
		if contentKey, err = NewContentKey(); err != nil {
			return nil, err
		}
	}

	encryptOpts := []EncryptOption{}
	if params.Passcode != "" {
		encryptOpts = append(encryptOpts, WithPasscode(params.Passcode))
	}
	blob, err := EncryptContent(contentKey, params.Fields, encryptOpts...)
	if err != nil {
		return nil, err
	}
	token, err := AccessToken(contentKey)
	if err != nil {
		return nil, err
	}

	itemKeyWrap := params.ItemKeyWrap
	if params.Custody {
		if itemKeyWrap != "" {
			return nil, fmt.Errorf("%w: set either Custody or ItemKeyWrap, not both", ErrInvalidField)
		}
		if itemKeyWrap, err = c.Credential.WrapToCustody(contentKey); err != nil {
			return nil, err
		}
	}

	body := map[string]any{
		"title":           params.Title,
		"encryption_type": encryptionType,
		"data":            blob,
		"access_token":    token,
	}
	if itemKeyWrap != "" {
		body["item_key_wrap"] = itemKeyWrap
	}
	if params.OrganizationID != "" {
		body["organization_id"] = params.OrganizationID
	}
	if params.Description != "" {
		body["description"] = params.Description
	}
	if params.Passcode != "" {
		verifier, err := PasscodeVerifier(params.Passcode)
		if err != nil {
			return nil, err
		}
		body["passcode_verifier"] = verifier
	}
	if params.ExpiredAt != "" {
		body["expired_at"] = params.ExpiredAt
	}
	if params.AccessCountsLeft > 0 {
		body["access_counts_left"] = params.AccessCountsLeft
	}
	if params.TimedView > 0 {
		body["timed_view"] = params.TimedView
	}

	idempotencyKey := params.IdempotencyKey
	if idempotencyKey == "" {
		// Required by the API, not optional. A retried automation must not create a second
		// copy of a credential in the world, with its own link and audit trail, that the
		// caller does not know exists.
		if idempotencyKey, err = randomToken(); err != nil {
			return nil, err
		}
	}

	data, err := c.request(ctx, http.MethodPost, "/shares", body, nil,
		map[string]string{"Idempotency-Key": idempotencyKey})
	if err != nil {
		return nil, err
	}

	shortCode, _ := data["short_code"].(string)
	link, err := c.LinkFor(shortCode, contentKey)
	if err != nil {
		return nil, err
	}

	share := &Share{ShortCode: shortCode, Link: link, ContentKey: contentKey}
	if expired, ok := data["expired_at"].(string); ok {
		share.ExpiredAt = &expired
	}
	if custody, ok := data["custody"].(string); ok {
		share.Custody = custody
	}
	return share, nil
}

// ListShares returns one page of the account's shares, newest first. Metadata only.
func (c *Client) ListShares(ctx context.Context, limit, page int) (*SharePage, error) {
	if limit <= 0 {
		limit = 25
	}
	if page <= 0 {
		page = 1
	}

	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	query.Set("page", strconv.Itoa(page))

	data, err := c.request(ctx, http.MethodGet, "/shares", nil, query, nil)
	if err != nil {
		return nil, err
	}

	result := &SharePage{Page: page, Limit: limit}
	if rows, ok := data["shares"].([]any); ok {
		for _, row := range rows {
			entry, ok := row.(map[string]any)
			if !ok {
				continue
			}
			summary := ShareSummary{}
			if code, ok := entry["short_code"].(string); ok {
				summary.ShortCode = code
			}
			if expired, ok := entry["expired_at"].(string); ok {
				summary.ExpiredAt = &expired
			}
			result.Shares = append(result.Shares, summary)
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

// IterateShares walks every page, calling fn for each share.
//
// Written here because the hand-rolled version is usually wrong in the same way: it stops on
// the first page shorter than the limit, which is a page the server is entitled to return in
// the middle of a result set. Returning a non-nil error from fn stops the walk.
func (c *Client) IterateShares(ctx context.Context, limit int, fn func(ShareSummary) error) error {
	if limit <= 0 {
		limit = 100
	}
	for page := 1; ; page++ {
		batch, err := c.ListShares(ctx, limit, page)
		if err != nil {
			return err
		}
		// The server echoes the page number, and HasMore compares that echo against
		// TotalPages. A server that echoes a constant therefore either stops on page one or
		// loops forever. Terminate on the counter this loop controls instead.
		if batch.Page != page {
			return fmt.Errorf(
				"%w: asked for page %d and the API answered with page %d, so paging cannot "+
					"be trusted to terminate", ErrAPI, page, batch.Page,
			)
		}
		for _, share := range batch.Shares {
			if err := fn(share); err != nil {
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
		if len(batch.Shares) < limit {
			return nil
		}
	}
}

// GetShare returns one share's metadata.
//
// It does not consume a view, evaluate a passcode, or return content. A share belonging to
// another account reports exactly as one that does not exist.
func (c *Client) GetShare(ctx context.Context, shortCode string) (*ShareSummary, error) {
	data, err := c.request(ctx, http.MethodGet, "/shares/"+url.PathEscape(shortCode), nil, nil, nil)
	if err != nil {
		return nil, err
	}
	summary := &ShareSummary{ShortCode: shortCode}
	if code, ok := data["short_code"].(string); ok {
		summary.ShortCode = code
	}
	if expired, ok := data["expired_at"].(string); ok {
		summary.ExpiredAt = &expired
	}
	return summary, nil
}

// ExpireShare expires a share immediately.
//
// Irreversible: afterwards the content is unrecoverable by anyone, including CredenShare — the
// key was never ours, and now the ciphertext is gone too.
//
// The share is REMOVED, not flagged. A later GetShare returns ErrNotFound rather than a row
// with an expiry set, and it drops out of ListShares. Worth knowing if you reconcile against
// your own records: a share you expired and one that never existed look identical afterwards.
//
// A key can only expire shares its own account created. A short code belonging to somebody
// else reports as not-found, so this cannot be used to probe for shares elsewhere.
func (c *Client) ExpireShare(ctx context.Context, shortCode string) error {
	_, err := c.request(ctx, http.MethodDelete, "/shares/"+url.PathEscape(shortCode), nil, nil, nil)
	return err
}

func (c *Client) request(
	ctx context.Context,
	method, path string,
	body any,
	query url.Values,
	headers map[string]string,
) (map[string]any, error) {
	authorization := "Bearer " + c.Credential.bearer()
	// Belt and braces. bearer() is assembled from parts so a custody secret cannot reach the
	// header, but this asserts the property at the boundary rather than trusting a constructor
	// in another file.
	if c.Credential.custodySecret != "" && strings.Contains(authorization, c.Credential.custodySecret) {
		return nil, fmt.Errorf("%w; rotate this credential", ErrCustodySecretTransmitted)
	}

	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return nil, fmt.Errorf("serialising the request: %w", err)
		}
	}

	var lastErr error
	for attempt := 0; ; attempt++ {
		var reader io.Reader
		if payload != nil {
			// A fresh reader each attempt: a consumed one would send an empty body on the
			// retry, which the server would see as a new body under a used Idempotency-Key.
			reader = bytes.NewReader(payload)
		}

		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", authorization)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		for key, value := range headers {
			req.Header.Set(key, value)
		}

		response, err := c.httpClient.Do(req)
		if err != nil {
			// Retry only the failures that prove nothing was received. A 5xx might have
			// committed and this client cannot tell, so it is surfaced rather than repeated.
			lastErr = err
			if ctx.Err() != nil || attempt >= c.maxRetries {
				// ErrServiceUnavailable is documented as "nothing was created", which is an
				// answer from the API. Never reaching it is not that answer, and a caller
				// who treats it as one retries a create with a fresh key and mints a second
				// copy of the same secret.
				return nil, fmt.Errorf(
					"%w: could not reach the API after %d attempt(s): %v",
					ErrDeliveryUnknown, attempt+1, lastErr,
				)
			}
			// Plain exponential backoff, no jitter: the retry count is 2 by default, so a
			// thundering herd is not the failure mode worth complicating this for.
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(500*(1<<attempt)) * time.Millisecond):
			}
			continue
		}

		raw, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("reading the response: %w", readErr)
		}

		parsed := map[string]any{}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &parsed)
		}

		if response.StatusCode >= 200 && response.StatusCode < 300 {
			return parsed, nil
		}
		return nil, errorFor(response, parsed, raw)
	}
}

func errorFor(response *http.Response, parsed map[string]any, raw []byte) error {
	message := fmt.Sprintf("HTTP %d", response.StatusCode)
	if text, ok := parsed["message"].(string); ok && text != "" {
		message = text
	} else if len(raw) > 0 {
		message = string(raw[:min(len(raw), 200)])
	}

	code := intFrom(parsed["error_code"], 0)
	requestID := response.Header.Get("X-Request-Id")
	if requestID == "" {
		requestID = response.Header.Get("X-Amzn-Requestid")
	}

	apiErr := &APIError{
		Message:   message,
		Status:    response.StatusCode,
		Code:      code,
		RequestID: requestID,
	}

	switch response.StatusCode {
	case http.StatusUnauthorized:
		apiErr.kind = ErrAuthentication
	case http.StatusForbidden:
		// A spent allowance is a 403 like a missing scope, but the remedies are opposite: one
		// needs a plan change, the other a different key. The numeric code separates them.
		if code == quotaExceededCode {
			apiErr.kind = ErrQuotaExceeded
		} else {
			apiErr.kind = ErrPermission
		}
	case http.StatusNotFound:
		apiErr.kind = ErrNotFound
	case http.StatusConflict:
		if code == idempotencyConflictCode {
			apiErr.kind = ErrIdempotencyConflict
		} else {
			apiErr.kind = ErrAPI
		}
	case http.StatusTooManyRequests:
		apiErr.kind = ErrRateLimited
		if after, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil {
			apiErr.RetryAfter = after
		}
	case http.StatusServiceUnavailable:
		apiErr.kind = ErrServiceUnavailable
	default:
		// Without this, a 400 or a 500 produced an APIError that errors.Is matched against
		// nothing, so the documented "check the sentinel" pattern silently fell through for
		// the two statuses a caller is most likely to hit.
		apiErr.kind = ErrAPI
	}
	return apiErr
}

func intFrom(value any, fallback int) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case json.Number:
		if parsed, err := typed.Int64(); err == nil {
			return int(parsed)
		}
	}
	return fallback
}

func randomToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generating an idempotency key: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

const userAgent = "credenshare-go/" + Version

// Version of this SDK.
const Version = "0.1.2"
