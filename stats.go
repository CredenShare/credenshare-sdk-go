package credenshare

// The account's usage figures.
//
// The endpoint an automation reaches for first, and the reason it exists: a nightly job
// asking "how much of the plan is left" should not have to page the entire share list to
// count. Scoped to the organization when the credential acts in one.

import (
	"context"
	"net/http"
)

// A DailyView is one day's view count.
type DailyView struct {
	// Date is the API's own date string, YYYY-MM-DD, kept as a string rather than parsed:
	// these are calendar buckets the server has already decided, and turning them into
	// time.Time here would attach this process's location to a day that has none.
	Date  string `json:"date"`
	Count int    `json:"count"`
}

// ShareCounts is the shares breakdown on Stats.
//
// Its own type, nested under Stats.Shares, rather than three flattened members: the API nests
// them, the specification nests them, and the sibling SDKs nest them, so the same expression
// reads the same in all four. Flattening also puts an Active next to a view series on one
// struct, where "active what" stops being obvious.
type ShareCounts struct {
	// Active, Expired and TotalViewed are the API's shares.active, shares.expired and
	// shares.total_viewed.
	Active      int
	Expired     int
	TotalViewed int
}

// Stats is the account's usage figures.
//
// The per-member breakdown the dashboard shows is deliberately absent from the API: a
// credential scoped to read statistics should not become a way to enumerate colleagues. So
// there is nothing to expose here, rather than something missing.
type Stats struct {
	// Shares is the counts breakdown. Zero-valued when the API sent no shares object, which
	// is not a state the deployed API produces.
	Shares ShareCounts

	// DailyViews is a contiguous window, OLDEST FIRST and zero-filled — the series the
	// dashboard sparkline draws. Always present and possibly empty, so an empty slice means
	// no views rather than no data: do not treat length zero as "the field was absent".
	//
	// Zero-filled matters if you compute your own deltas. A day with no views is a bucket
	// with a count of 0, not a gap, so consecutive entries are consecutive days.
	DailyViews []DailyView
}

// GetStats returns the account's usage figures.
func (c *Client) GetStats(ctx context.Context) (*Stats, error) {
	data, err := c.request(ctx, http.MethodGet, "/stats", nil, nil, nil)
	if err != nil {
		return nil, err
	}

	stats := &Stats{}
	if shares, ok := data["shares"].(map[string]any); ok {
		stats.Shares = ShareCounts{
			Active:      intFrom(shares["active"], 0),
			Expired:     intFrom(shares["expired"], 0),
			TotalViewed: intFrom(shares["total_viewed"], 0),
		}
	}
	// Kept as a nil slice when the series is empty, not as a zero-length one: the two are
	// interchangeable to every reader in Go, and inventing an allocation to distinguish
	// them would suggest a difference that the API does not make.
	if buckets, ok := data["daily_views"].([]any); ok {
		for _, bucket := range buckets {
			entry, ok := bucket.(map[string]any)
			if !ok {
				continue
			}
			view := DailyView{Count: intFrom(entry["count"], 0)}
			if date, ok := entry["date"].(string); ok {
				view.Date = date
			}
			stats.DailyViews = append(stats.DailyViews, view)
		}
	}
	return stats, nil
}
