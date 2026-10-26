package credenshare

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

func accessLogBody(next any) map[string]any {
	return map[string]any{
		"short_code": "AbC123",
		"entries": []any{
			map[string]any{
				"accessed_at": "2026-10-25T18:00:00Z", "accessed_ip": "203.0.113.7",
				"platform": "macOS", "user_agent": "Mozilla/5.0", "failed_passcode": false,
				"signed_in": true,
			},
			map[string]any{
				"accessed_at": "2026-10-25T17:00:00Z", "accessed_ip": "198.51.100.2",
				"platform": "Linux", "user_agent": nil, "failed_passcode": true, "signed_in": false,
			},
		},
		"next_cursor":    next,
		"retention_days": 90,
		"effective_from": "2026-07-27T18:00:00Z",
		"effective_to":   "2026-10-25T18:00:00Z",
	}
}

func queryOf(t *testing.T, raw string) url.Values {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Query()
}

func TestTheAccessLogReadsAPageAndItsWindow(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{
		status: 200, body: accessLogBody("eyJjdXJzb3IiOjF9"), headers: map[string]string{"ETag": `W/"abc"`},
	}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.GetAccessLog(context.Background(), "AbC123", &AccessLogOptions{
		Limit:  10,
		Cursor: "prev",
		From:   time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
		To:     time.Date(2026, 10, 31, 23, 59, 59, 0, time.FixedZone("EST", -5*3600)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if page.ShortCode != "AbC123" || len(page.Entries) != 2 || page.RetentionDays != 90 {
		t.Fatalf("page = %+v", page)
	}
	first, second := page.Entries[0], page.Entries[1]
	if first.AccessedIP != "203.0.113.7" || first.UserAgent == nil || *first.UserAgent != "Mozilla/5.0" ||
		!first.SignedIn || first.FailedPasscode {
		t.Fatalf("first entry = %+v", first)
	}
	// A null user agent stays nil rather than becoming an empty string a caller would match on.
	if second.UserAgent != nil || !second.FailedPasscode || second.SignedIn {
		t.Fatalf("second entry = %+v", second)
	}
	if page.NextCursor != "eyJjdXJzb3IiOjF9" || !page.HasMore() || page.ETag != `W/"abc"` || page.NotModified {
		t.Fatalf("paging = %+v", page)
	}
	if page.EffectiveFrom != "2026-07-27T18:00:00Z" || page.EffectiveTo != "2026-10-25T18:00:00Z" {
		t.Fatalf("window = %s .. %s", page.EffectiveFrom, page.EffectiveTo)
	}

	sent := rec.requests[0]
	if !strings.Contains(sent.URL, "/shares/AbC123/access-log?") || sent.Method != "GET" {
		t.Fatalf("request = %s %s", sent.Method, sent.URL)
	}
	q := queryOf(t, sent.URL)
	// Times go out in UTC, RFC 3339, whatever zone the caller's time.Time carried.
	if q.Get("limit") != "10" || q.Get("cursor") != "prev" || q.Get("from") != "2026-10-01T00:00:00Z" ||
		q.Get("to") != "2026-11-01T04:59:59Z" {
		t.Fatalf("query = %v", q)
	}
	if sent.Headers.Get("If-None-Match") != "" || sent.Headers.Get("Idempotency-Key") != "" {
		t.Fatalf("headers = %v", sent.Headers)
	}
}

func TestAnUnboundedAccessLogReadSendsNoQuery(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: accessLogBody(nil)}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.GetAccessLog(context.Background(), "a/b", nil)
	if err != nil {
		t.Fatal(err)
	}
	if page.HasMore() || page.NextCursor != "" {
		t.Fatalf("a null next_cursor is the last page: %+v", page)
	}
	if !strings.HasSuffix(rec.requests[0].URL, "/shares/a%2Fb/access-log") {
		t.Fatalf("url = %s", rec.requests[0].URL)
	}
}

func TestAnUnchangedAccessLogIsNotModifiedRatherThanAnError(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 304, headers: map[string]string{"ETag": `W/"abc"`}}}}
	client := newTestClient(t, rec, testCredential)

	page, err := client.GetAccessLog(context.Background(), "AbC123", &AccessLogOptions{IfNoneMatch: `W/"abc"`})
	if err != nil {
		t.Fatalf("a 304 surfaced as %v", err)
	}
	if !page.NotModified || page.ETag != `W/"abc"` || page.Entries != nil || page.ShortCode != "AbC123" {
		t.Fatalf("page = %+v", page)
	}
	if got := rec.requests[0].Headers.Get("If-None-Match"); got != `W/"abc"` {
		t.Fatalf("If-None-Match = %q", got)
	}
}

func TestAccessLogRefusalsMapToTheirSentinels(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
	}{{403, ErrPermission}, {404, ErrNotFound}, {400, ErrAPI}} {
		rec := &recorder{responses: []stubResponse{{status: tc.status, body: map[string]any{"message": "no"}}}}
		client := newTestClient(t, rec, testCredential)
		_, err := client.GetAccessLog(context.Background(), "AbC123", nil)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%d gave %v, want %v", tc.status, err, tc.want)
		}
	}
}

func TestAccessLogOptionsAreCheckedBeforeAnyRequest(t *testing.T) {
	from := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	for _, opts := range []*AccessLogOptions{
		{Limit: 101}, {Limit: -1}, {From: from, To: from.Add(-time.Hour)},
	} {
		rec := &recorder{}
		client := newTestClient(t, rec, testCredential)
		if _, err := client.GetAccessLog(context.Background(), "AbC123", opts); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%+v gave %v", opts, err)
		}
		if len(rec.requests) != 0 {
			t.Fatalf("%+v reached the API", opts)
		}
	}
}

func TestIterateAccessLogFollowsTheCursorToTheEnd(t *testing.T) {
	rec := &recorder{responses: []stubResponse{
		{status: 200, body: accessLogBody("c1")},
		{status: 200, body: accessLogBody("c2")},
		{status: 200, body: accessLogBody(nil)},
	}}
	client := newTestClient(t, rec, testCredential)

	var seen int
	err := client.IterateAccessLog(context.Background(), "AbC123",
		&AccessLogOptions{Limit: 2, IfNoneMatch: `W/"x"`}, func(AccessLogEntry) error {
			seen++
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if seen != 6 || len(rec.requests) != 3 {
		t.Fatalf("seen %d entries over %d requests", seen, len(rec.requests))
	}
	if c := queryOf(t, rec.requests[1].URL).Get("cursor"); c != "c1" {
		t.Fatalf("second page cursor = %q", c)
	}
	if c := queryOf(t, rec.requests[2].URL).Get("cursor"); c != "c2" {
		t.Fatalf("third page cursor = %q", c)
	}
	for _, sent := range rec.requests {
		// A walk never revalidates: a 304 on page one would end it having read nothing.
		if sent.Headers.Get("If-None-Match") != "" {
			t.Fatalf("a walk sent If-None-Match")
		}
		if queryOf(t, sent.URL).Get("limit") != "2" {
			t.Fatalf("limit lost on %s", sent.URL)
		}
	}
}

func TestIterateAccessLogRefusesACursorThatDoesNotMove(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: accessLogBody("same")}}}
	client := newTestClient(t, rec, testCredential)
	err := client.IterateAccessLog(context.Background(), "AbC123", nil, func(AccessLogEntry) error { return nil })
	if !errors.Is(err, ErrAPI) || len(rec.requests) != 2 {
		t.Fatalf("got %v after %d requests", err, len(rec.requests))
	}
}

func TestTheOldListsSendTheBytesTheyAlwaysHave(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{"shares": []any{}}}}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.ListShares(context.Background(), 25, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListRequests(context.Background(), 25, 1); err != nil {
		t.Fatal(err)
	}
	for _, sent := range rec.requests {
		if strings.Contains(sent.URL, "status") {
			t.Fatalf("an unchanged call now sends a status: %s", sent.URL)
		}
	}
}

func TestTheExpiredListsAskForThem(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"shares":     []any{map[string]any{"short_code": "old1", "expired_at": "2026-10-20T00:00:00Z"}},
		"requests":   []any{map[string]any{"short_code": "req1", "expired_at": "2026-10-20T00:00:00Z"}},
		"pagination": map[string]any{"page": 1, "limit": 25, "total": 1, "total_pages": 1},
	}}}}
	client := newTestClient(t, rec, testCredential)
	ctx := context.Background()

	shares, err := client.ListSharesByStatus(ctx, StatusExpired, 25, 1)
	if err != nil || len(shares.Shares) != 1 || shares.Shares[0].ShortCode != "old1" {
		t.Fatalf("shares = %+v, %v", shares, err)
	}
	if _, err := client.ListRequestsByStatus(ctx, StatusExpired, 25, 1); err != nil {
		t.Fatal(err)
	}
	var walked int
	if err := client.IterateSharesByStatus(ctx, StatusExpired, 25, func(ShareSummary) error { walked++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := client.IterateRequestsByStatus(ctx, StatusActive, 25, func(RequestSummary) error { walked++; return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"expired", "expired", "expired", "active"}
	for i, sent := range rec.requests {
		if got := queryOf(t, sent.URL).Get("status"); got != want[i] {
			t.Fatalf("request %d status = %q, want %q (%s)", i, got, want[i], sent.URL)
		}
	}
	if walked != 2 {
		t.Fatalf("walked %d", walked)
	}
}

func TestAnUnknownListStatusIsRefusedBeforeAnyRequest(t *testing.T) {
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	ctx := context.Background()
	noop := func(ShareSummary) error { return nil }
	for _, err := range []error{
		func() error { _, err := client.ListSharesByStatus(ctx, "archived", 25, 1); return err }(),
		func() error { _, err := client.ListRequestsByStatus(ctx, "", 25, 1); return err }(),
		client.IterateSharesByStatus(ctx, "Expired", 25, noop),
	} {
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("got %v", err)
		}
	}
	if len(rec.requests) != 0 {
		t.Fatalf("%d requests reached the API", len(rec.requests))
	}
}

func capabilitiesBody(org any, policy any) map[string]any {
	return map[string]any{
		"api_version": "1",
		"key": map[string]any{
			"key_id": "abc123", "scopes": []any{"shares:write", "audit:read"}, "custody_level": 1,
			"organization_id": org, "rate_limit_rpm": 100,
		},
		"plan": map[string]any{"code": "business", "name": "Business"},
		"limits": map[string]any{
			"max_shares": -1, "remaining_shares": -1, "max_fields": 20, "max_days_access_logs": 90,
			"max_api_keys": 10, "max_webhooks": 5,
		},
		"features":         map[string]any{"secure_requests": true, "zero_knowledge": false},
		"sharing_policy":   policy,
		"field_types":      []any{"text", "password", "date", "multiline", "markdown", "source_code", "url", "qr"},
		"notify_on_events": []any{"viewed", "denied", "expired", "deleted"},
	}
}

func TestCapabilitiesForAPersonalKey(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{
		status: 200, body: capabilitiesBody(nil, nil), headers: map[string]string{"ETag": `W/"cap"`},
	}}}
	client := newTestClient(t, rec, testCredential)

	caps, err := client.GetCapabilities(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if caps.APIVersion != "1" || caps.Key.KeyID != "abc123" || len(caps.Key.Scopes) != 2 ||
		caps.Key.CustodyLevel != 1 || caps.Key.OrganizationID != nil || caps.Key.RateLimitRPM != 100 {
		t.Fatalf("key = %+v", caps.Key)
	}
	if caps.Plan != (CapabilityPlan{Code: "business", Name: "Business"}) {
		t.Fatalf("plan = %+v", caps.Plan)
	}
	if caps.Limits.MaxShares != Unlimited || caps.Limits.MaxDaysAccessLogs != 90 || caps.Limits.MaxWebhooks != 5 {
		t.Fatalf("limits = %+v", caps.Limits)
	}
	if !caps.Features["secure_requests"] || caps.Features["zero_knowledge"] {
		t.Fatalf("features = %+v", caps.Features)
	}
	// The API publishes the field types the recipient view renders; they must match this SDK's.
	if strings.Join(caps.FieldTypes, ",") != strings.Join(FieldTypes, ",") ||
		strings.Join(caps.NotifyOnEvents, ",") != strings.Join(NotifyOnEvents, ",") {
		t.Fatalf("lists = %v %v", caps.FieldTypes, caps.NotifyOnEvents)
	}
	if caps.SharingPolicy != nil || caps.ETag != `W/"cap"` || caps.NotModified {
		t.Fatalf("caps = %+v", caps)
	}
	if !strings.HasSuffix(rec.requests[0].URL, "/capabilities") {
		t.Fatalf("url = %s", rec.requests[0].URL)
	}
}

func TestCapabilitiesForATeamKeyCarryItsPolicy(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: capabilitiesBody(
		"org-1", map[string]any{"require_passcode": true},
	)}}}
	client := newTestClient(t, rec, testCredential)
	caps, err := client.GetCapabilities(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if caps.Key.OrganizationID == nil || *caps.Key.OrganizationID != "org-1" {
		t.Fatalf("organization = %v", caps.Key.OrganizationID)
	}
	if caps.SharingPolicy["require_passcode"] != true {
		t.Fatalf("policy = %v", caps.SharingPolicy)
	}
}

func TestUnchangedCapabilitiesAreNotModified(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 304, headers: map[string]string{"ETag": `W/"cap"`}}}}
	client := newTestClient(t, rec, testCredential)
	caps, err := client.GetCapabilities(context.Background(), &CapabilitiesOptions{IfNoneMatch: `W/"cap"`})
	if err != nil || !caps.NotModified || caps.ETag != `W/"cap"` {
		t.Fatalf("caps = %+v, %v", caps, err)
	}
	if rec.requests[0].Headers.Get("If-None-Match") != `W/"cap"` {
		t.Fatalf("If-None-Match not sent")
	}
}

func TestAnUnaskedNotModifiedStillFailsTheOtherReads(t *testing.T) {
	// Only the conditional reads accept a 304. Elsewhere it is not an answer the method can
	// return, and reporting it as success would hand back an empty page as though it were real.
	rec := &recorder{responses: []stubResponse{{status: 304}}}
	client := newTestClient(t, rec, testCredential)
	if _, err := client.GetStats(context.Background()); !errors.Is(err, ErrAPI) {
		t.Fatalf("got %v", err)
	}
}

func TestNotifyOnIsSentWhenSetAndAbsentOtherwise(t *testing.T) {
	rec := &recorder{}
	client := newTestClient(t, rec, testCredential)
	ctx := context.Background()

	if _, err := client.CreateShare(ctx, CreateParams{
		Title: "t", Fields: []Field{testField}, NotifyOn: []string{"viewed", "denied"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateShare(ctx, CreateParams{Title: "t", Fields: []Field{testField}}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.requests[0].Body, `"notify_on":["viewed","denied"]`) {
		t.Fatalf("body = %s", rec.requests[0].Body)
	}
	if strings.Contains(rec.requests[1].Body, "notify_on") {
		t.Fatalf("an unset NotifyOn reached the body: %s", rec.requests[1].Body)
	}
}

func TestNotifyOnIsCheckedAsTheAPIChecksIt(t *testing.T) {
	for _, events := range [][]string{
		{"opened"}, {"viewed", "viewed"}, {"Viewed"},
		{"viewed", "denied", "expired", "deleted", "viewed"},
	} {
		rec := &recorder{}
		client := newTestClient(t, rec, testCredential)
		_, err := client.CreateShare(context.Background(), CreateParams{
			Title: "t", Fields: []Field{testField}, NotifyOn: events,
		})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("%v gave %v", events, err)
		}
		if len(rec.requests) != 0 {
			t.Fatalf("%v reached the API", events)
		}
	}
}
