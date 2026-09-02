package credenshare

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestStatsCarriesTheCountsAndTheSeries(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"shares": map[string]any{"active": 12, "expired": 3, "total_viewed": 40},
		"daily_views": []any{
			map[string]any{"date": "2026-08-31", "count": 0},
			map[string]any{"date": "2026-09-01", "count": 7},
		},
	}}}}
	client := newTestClient(t, rec, testCredential)

	stats, err := client.GetStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Nested, matching the API, the specification and the sibling SDKs.
	if stats.Shares != (ShareCounts{Active: 12, Expired: 3, TotalViewed: 40}) {
		t.Fatalf("stats.Shares = %+v", stats.Shares)
	}
	if len(stats.DailyViews) != 2 {
		t.Fatalf("daily views = %+v", stats.DailyViews)
	}
	// Oldest first, and zero-filled: a day with no views is a bucket with a count of 0, not
	// a gap, so consecutive entries are consecutive days. A caller computing deltas depends
	// on that order being preserved rather than sorted by whatever a map iteration gave.
	if stats.DailyViews[0].Date != "2026-08-31" || stats.DailyViews[0].Count != 0 {
		t.Fatalf("first bucket = %+v", stats.DailyViews[0])
	}
	if stats.DailyViews[1].Count != 7 {
		t.Fatalf("second bucket = %+v", stats.DailyViews[1])
	}
	if rec.requests[0].Method != http.MethodGet || !strings.HasSuffix(rec.requests[0].URL, "/stats") {
		t.Fatalf("request = %+v", rec.requests[0])
	}
	if got := rec.requests[0].Headers.Get("Idempotency-Key"); got != "" {
		t.Fatalf("a read carried Idempotency-Key %q", got)
	}
}

func TestAnEmptySeriesIsNoViewsRatherThanNoData(t *testing.T) {
	// daily_views is always present and possibly empty, so an empty series is an answer.
	// Erroring here, or reporting it as missing, would make a quiet week look like an outage.
	rec := &recorder{responses: []stubResponse{{status: 200, body: map[string]any{
		"shares":      map[string]any{"active": 0, "expired": 0, "total_viewed": 0},
		"daily_views": []any{},
	}}}}
	client := newTestClient(t, rec, testCredential)

	stats, err := client.GetStats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(stats.DailyViews) != 0 {
		t.Fatalf("daily views = %+v", stats.DailyViews)
	}
}

func TestStatsWithoutTheScopeIsAPermissionRefusal(t *testing.T) {
	// Missing stats:read is a 403 without a quota code, and the remedy is a different key
	// rather than a plan change.
	rec := &recorder{responses: []stubResponse{{
		status: 403, body: map[string]any{"message": "insufficient role"},
	}}}
	client := newTestClient(t, rec, testCredential)

	_, err := client.GetStats(context.Background())
	if !errors.Is(err, ErrPermission) || errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("got %v", err)
	}
}
