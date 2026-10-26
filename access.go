package credenshare

// Who opened a share, what a key may do, and which list to read: the /v1 additions of
// CredenShare's Gitea #404.

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// A ListStatus picks the active or the expired half of the share and request lists.
type ListStatus string

const (
	// StatusActive is the live list, and what ListShares and ListRequests have always read.
	StatusActive ListStatus = "active"
	// StatusExpired is the ended half: shares that expired by date, by views or by deletion,
	// and requests that have closed.
	StatusExpired ListStatus = "expired"
)

func (s ListStatus) validate() error {
	if s == StatusActive || s == StatusExpired {
		return nil
	}
	return fmt.Errorf("%w: a list status is %q or %q, not %q",
		ErrInvalidArgument, StatusActive, StatusExpired, string(s))
}

// Unlimited is the value a limit takes when the plan sets none, in CapabilityLimits and in
// AccessLogPage.RetentionDays.
const Unlimited = -1

// AccessLogOptions narrow one read of a share's access log. The zero value reads the newest
// page at the API's default size.
type AccessLogOptions struct {
	// Limit is 1 to 100. Zero leaves it to the API, which answers 50.
	Limit int

	// Cursor is a previous page's NextCursor, to read further back. Opaque.
	Cursor string

	// From and To bound the entries by time. Zero means unbounded on that side. The plan's
	// retention still applies: nothing older than RetentionDays comes back, whatever From says.
	From, To time.Time

	// IfNoneMatch is an ETag from an earlier page. When the page is unchanged the API answers
	// 304, which GetAccessLog returns as a page with NotModified set rather than as an error.
	IfNoneMatch string
}

// An AccessLogEntry is one opening of a share.
type AccessLogEntry struct {
	// AccessedAt is the API's RFC 3339 time, kept as the string it sent.
	AccessedAt string
	AccessedIP string
	Platform   string

	// UserAgent is the viewer's raw user agent, or nil when none was recorded. Link-preview
	// bots and scanners show up here, and telling them apart is left to the caller.
	UserAgent *string

	// FailedPasscode is true when the viewer entered a wrong passcode.
	FailedPasscode bool

	// SignedIn is true when the viewer was signed in to CredenShare. Whose account it was is
	// not disclosed to an API key.
	SignedIn bool
}

// An AccessLogPage is one page of a share's access log, newest first.
type AccessLogPage struct {
	ShortCode string
	Entries   []AccessLogEntry

	// NextCursor reads the next, older page. Empty on the last page.
	NextCursor string

	// RetentionDays is the plan's access-log retention, or Unlimited.
	RetentionDays int

	// EffectiveFrom and EffectiveTo are the window the API applied after retention, as RFC 3339
	// strings. When From and To are not set they move with the clock, so the ETag of an
	// unbounded read changes from one second to the next.
	EffectiveFrom string
	EffectiveTo   string

	// ETag revalidates this page later, through AccessLogOptions.IfNoneMatch.
	ETag string

	// NotModified is true when the API answered 304 to IfNoneMatch. Nothing else is set then,
	// except ShortCode and ETag: the page the caller already holds is still current.
	NotModified bool
}

// HasMore reports whether an older page exists.
func (p *AccessLogPage) HasMore() bool { return p.NextCursor != "" }

func (o *AccessLogOptions) query() (url.Values, error) {
	query := url.Values{}
	if o == nil {
		return query, nil
	}
	if o.Limit < 0 || o.Limit > 100 {
		return nil, fmt.Errorf("%w: an access log Limit is 1 to 100, got %d", ErrInvalidArgument, o.Limit)
	}
	if !o.From.IsZero() && !o.To.IsZero() && o.From.After(o.To) {
		return nil, fmt.Errorf("%w: the access log's From is after its To", ErrInvalidArgument)
	}
	if o.Limit > 0 {
		query.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Cursor != "" {
		query.Set("cursor", o.Cursor)
	}
	if !o.From.IsZero() {
		query.Set("from", o.From.UTC().Format(time.RFC3339))
	}
	if !o.To.IsZero() {
		query.Set("to", o.To.UTC().Format(time.RFC3339))
	}
	return query, nil
}

// GetAccessLog returns one page of a share's access log: who opened it, newest first, the
// history the app shows under Access History.
//
// The credential needs the audit:read scope, which shares:read does not include because the log
// carries recipients' IP addresses; without it this is ErrPermission. Only the share's creator
// can read the log, for a live share or one that has ended, and any other short code is
// ErrNotFound. A bad Limit, time or cursor that reaches the API is ErrAPI with status 400.
func (c *Client) GetAccessLog(
	ctx context.Context, shortCode string, opts *AccessLogOptions,
) (*AccessLogPage, error) {
	query, err := opts.query()
	if err != nil {
		return nil, err
	}
	var headers map[string]string
	if opts != nil && opts.IfNoneMatch != "" {
		headers = map[string]string{"If-None-Match": opts.IfNoneMatch}
	}

	reply, err := c.exchange(ctx, http.MethodGet,
		"/shares/"+url.PathEscape(shortCode)+"/access-log", nil, query, headers, true)
	if err != nil {
		return nil, err
	}

	page := &AccessLogPage{ShortCode: shortCode, ETag: reply.etag, NotModified: reply.notModified}
	if reply.notModified {
		return page, nil
	}
	data := reply.data
	if code, ok := data["short_code"].(string); ok && code != "" {
		page.ShortCode = code
	}
	if rows, ok := data["entries"].([]any); ok {
		for _, row := range rows {
			if entry, ok := row.(map[string]any); ok {
				page.Entries = append(page.Entries, accessLogEntryFrom(entry))
			}
		}
	}
	if next, ok := data["next_cursor"].(string); ok {
		page.NextCursor = next
	}
	page.RetentionDays = intFrom(data["retention_days"], 0)
	page.EffectiveFrom, _ = data["effective_from"].(string)
	page.EffectiveTo, _ = data["effective_to"].(string)
	return page, nil
}

func accessLogEntryFrom(entry map[string]any) AccessLogEntry {
	out := AccessLogEntry{}
	out.AccessedAt, _ = entry["accessed_at"].(string)
	out.AccessedIP, _ = entry["accessed_ip"].(string)
	out.Platform, _ = entry["platform"].(string)
	if agent, ok := entry["user_agent"].(string); ok {
		out.UserAgent = &agent
	}
	out.FailedPasscode, _ = entry["failed_passcode"].(bool)
	out.SignedIn, _ = entry["signed_in"].(bool)
	return out
}

// IterateAccessLog walks a share's access log from the newest entry back, following each page's
// NextCursor, and calls fn for every entry. Returning a non-nil error from fn stops the walk.
//
// opts may set Limit, From, To, and a Cursor to start from. IfNoneMatch is ignored: a walk reads
// every page, and a 304 on the first would end it with nothing read.
func (c *Client) IterateAccessLog(
	ctx context.Context, shortCode string, opts *AccessLogOptions, fn func(AccessLogEntry) error,
) error {
	walk := AccessLogOptions{}
	if opts != nil {
		walk = *opts
	}
	walk.IfNoneMatch = ""
	for pages := 1; ; pages++ {
		if pages > maxPages {
			return fmt.Errorf("%w: the access log did not end within %d pages, so it is not being "+
				"walked any further", ErrAPI, maxPages)
		}
		page, err := c.GetAccessLog(ctx, shortCode, &walk)
		if err != nil {
			return err
		}
		for _, entry := range page.Entries {
			if err := fn(entry); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		// A cursor that does not move would repeat the same page forever.
		if page.NextCursor == walk.Cursor {
			return fmt.Errorf("%w: the access log returned the cursor it was given, so paging "+
				"cannot be trusted to terminate", ErrAPI)
		}
		walk.Cursor = page.NextCursor
	}
}

// CapabilitiesOptions are for GetCapabilities. A nil value is a plain read.
type CapabilitiesOptions struct {
	// IfNoneMatch is an ETag from an earlier read; an unchanged answer comes back with
	// NotModified set rather than as an error.
	IfNoneMatch string
}

// CapabilityKey is the credential itself, as the API sees it.
type CapabilityKey struct {
	KeyID        string
	Scopes       []string
	CustodyLevel int
	// OrganizationID is the team a team key acts in, or nil for a personal key.
	OrganizationID *string
	RateLimitRPM   int
}

// CapabilityPlan is the plan behind the key: the team's for a team key, the account's otherwise.
type CapabilityPlan struct {
	Code string
	Name string
}

// CapabilityLimits are the plan's numeric limits, any negotiated override included. Unlimited
// (-1) means the plan sets none.
type CapabilityLimits struct {
	MaxShares         int
	RemainingShares   int
	MaxFields         int
	MaxDaysAccessLogs int
	MaxAPIKeys        int
	MaxWebhooks       int
}

// Capabilities is what a key may do: its scopes, its plan's limits and features, and the lists
// the API accepts.
type Capabilities struct {
	APIVersion string
	Key        CapabilityKey
	Plan       CapabilityPlan
	Limits     CapabilityLimits

	// Features are the plan's switches by the API's own names, such as "secure_requests" or
	// "zero_knowledge". A map rather than fields, so a feature the API adds later is readable
	// without a new release of this SDK.
	Features map[string]bool

	// SharingPolicy is the team's sharing policy for a team key, in the API's shape, so a
	// caller can meet it before creating anything. Nil for a personal key.
	SharingPolicy map[string]any

	// FieldTypes and NotifyOnEvents are the lists the API accepts, as it publishes them.
	FieldTypes     []string
	NotifyOnEvents []string

	ETag        string
	NotModified bool
}

// GetCapabilities returns what this credential may do. No scope is needed.
func (c *Client) GetCapabilities(ctx context.Context, opts *CapabilitiesOptions) (*Capabilities, error) {
	var headers map[string]string
	if opts != nil && opts.IfNoneMatch != "" {
		headers = map[string]string{"If-None-Match": opts.IfNoneMatch}
	}
	reply, err := c.exchange(ctx, http.MethodGet, "/capabilities", nil, nil, headers, true)
	if err != nil {
		return nil, err
	}
	caps := &Capabilities{ETag: reply.etag, NotModified: reply.notModified}
	if reply.notModified {
		return caps, nil
	}
	data := reply.data
	caps.APIVersion, _ = data["api_version"].(string)
	if key, ok := data["key"].(map[string]any); ok {
		caps.Key.KeyID, _ = key["key_id"].(string)
		caps.Key.Scopes = stringsFrom(key["scopes"])
		caps.Key.CustodyLevel = intFrom(key["custody_level"], 0)
		if org, ok := key["organization_id"].(string); ok && org != "" {
			caps.Key.OrganizationID = &org
		}
		caps.Key.RateLimitRPM = intFrom(key["rate_limit_rpm"], 0)
	}
	if plan, ok := data["plan"].(map[string]any); ok {
		caps.Plan.Code, _ = plan["code"].(string)
		caps.Plan.Name, _ = plan["name"].(string)
	}
	if limits, ok := data["limits"].(map[string]any); ok {
		caps.Limits = CapabilityLimits{
			MaxShares:         intFrom(limits["max_shares"], 0),
			RemainingShares:   intFrom(limits["remaining_shares"], 0),
			MaxFields:         intFrom(limits["max_fields"], 0),
			MaxDaysAccessLogs: intFrom(limits["max_days_access_logs"], 0),
			MaxAPIKeys:        intFrom(limits["max_api_keys"], 0),
			MaxWebhooks:       intFrom(limits["max_webhooks"], 0),
		}
	}
	if features, ok := data["features"].(map[string]any); ok {
		caps.Features = make(map[string]bool, len(features))
		for name, on := range features {
			caps.Features[name], _ = on.(bool)
		}
	}
	if policy, ok := data["sharing_policy"].(map[string]any); ok {
		caps.SharingPolicy = policy
	}
	caps.FieldTypes = stringsFrom(data["field_types"])
	caps.NotifyOnEvents = stringsFrom(data["notify_on_events"])
	return caps, nil
}

func stringsFrom(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
