package credenshare

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// A client with no link origin configured, so it asks the API (Gitea #412).
func newUnconfiguredClient(t *testing.T, rec *recorder) *Client {
	t.Helper()
	client, err := New(testCredential, &Options{
		HTTPClient: &http.Client{Transport: rec},
		MaxRetries: Retries(0),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func capabilitiesWithOrigin(origin any) map[string]any {
	body := capabilitiesBody("org-1", nil)
	body["link_origin"] = origin
	return body
}

func capabilityCalls(rec *recorder) int {
	n := 0
	for _, sent := range rec.requests {
		if strings.HasSuffix(sent.URL, "/capabilities") {
			n++
		}
	}
	return n
}

func TestATeamKeysLinksAreOnItsCustomDomain(t *testing.T) {
	rec := &recorder{responses: []stubResponse{
		{status: 201, body: map[string]any{"short_code": "abc123"}},
		{status: 200, body: capabilitiesWithOrigin("https://cd-test.credenshare.io")},
		{status: 201, body: map[string]any{"short_code": "def456"}},
	}}
	client := newUnconfiguredClient(t, rec)
	ctx := context.Background()

	first, err := client.CreateShare(ctx, CreateParams{Title: "t", Fields: []Field{testField}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.CreateShare(ctx, CreateParams{Title: "t", Fields: []Field{testField}})
	if err != nil {
		t.Fatal(err)
	}
	for _, share := range []*Share{first, second} {
		if !strings.HasPrefix(share.Link, "https://cd-test.credenshare.io/"+share.ShortCode+"#1") {
			t.Fatalf("link = %s", share.Link)
		}
	}
	if n := capabilityCalls(rec); n != 1 {
		t.Fatalf("capabilities was asked %d times across two creates", n)
	}
	// The link helpers agree with what the creates returned.
	link, _ := client.LinkFor(first.ShortCode, first.ContentKey)
	if link != first.Link || client.LinkOrigin(ctx) != "https://cd-test.credenshare.io" {
		t.Fatalf("LinkFor = %s, LinkOrigin = %s", link, client.LinkOrigin(ctx))
	}
	if n := capabilityCalls(rec); n != 1 {
		t.Fatalf("LinkOrigin asked again: %d", n)
	}
}

func TestAConfiguredOriginWinsAndNothingIsAsked(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 201, body: map[string]any{"short_code": "abc123"}}}}
	client, err := New(testCredential, &Options{
		LinkOrigin: "https://links.example.com/",
		HTTPClient: &http.Client{Transport: rec},
	})
	if err != nil {
		t.Fatal(err)
	}
	share, err := client.CreateShare(context.Background(), CreateParams{Title: "t", Fields: []Field{testField}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(share.Link, "https://links.example.com/abc123#") {
		t.Fatalf("link = %s", share.Link)
	}
	if n := capabilityCalls(rec); n != 0 || len(rec.requests) != 1 {
		t.Fatalf("a configured origin still asked: %d of %d requests", n, len(rec.requests))
	}
}

func TestNoTeamOriginOrAFailedAnswerGivesTheDefault(t *testing.T) {
	for name, capabilities := range map[string]stubResponse{
		"a null origin":       {status: 200, body: capabilitiesWithOrigin(nil)},
		"no member at all":    {status: 200, body: capabilitiesBody(nil, nil)},
		"a refusal":           {status: 403, body: map[string]any{"message": "no"}},
		"a server error":      {status: 500, body: map[string]any{"message": "boom"}},
		"a path, not origin":  {status: 200, body: capabilitiesWithOrigin("https://cd.example.com/evil")},
		"plain http":          {status: 200, body: capabilitiesWithOrigin("http://cd.example.com")},
		"credentials in it":   {status: 200, body: capabilitiesWithOrigin("https://user@cd.example.com")},
		"a query":             {status: 200, body: capabilitiesWithOrigin("https://cd.example.com?x=1")},
		"not a string at all": {status: 200, body: capabilitiesWithOrigin(42)},
	} {
		rec := &recorder{responses: []stubResponse{
			{status: 201, body: map[string]any{"short_code": "abc123"}},
			capabilities,
			{status: 201, body: map[string]any{"short_code": "def456"}},
		}}
		client := newUnconfiguredClient(t, rec)
		ctx := context.Background()
		for i := 0; i < 2; i++ {
			share, err := client.CreateShare(ctx, CreateParams{Title: "t", Fields: []Field{testField}})
			if err != nil {
				t.Fatalf("%s: the create failed: %v", name, err)
			}
			if !strings.HasPrefix(share.Link, DefaultLinkOrigin+"/") {
				t.Fatalf("%s: link = %s", name, share.Link)
			}
		}
		// The answer is kept, a "none" or a failure included: one question per client.
		if n := capabilityCalls(rec); n != 1 {
			t.Fatalf("%s: capabilities was asked %d times", name, n)
		}
	}
}

func TestASecureRequestsLinksAreOnTheTeamDomainToo(t *testing.T) {
	rec := &recorder{responses: []stubResponse{
		{status: 201, body: map[string]any{"short_code": "rq01"}},
		{status: 200, body: capabilitiesWithOrigin("https://cd-test.credenshare.io")},
	}}
	client := newUnconfiguredClient(t, rec)
	created, err := client.CreateRequest(context.Background(), CreateRequestParams{
		Title: "t", Fields: []RequestField{{Item: "Password", Type: "password"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.CollectLink != "https://cd-test.credenshare.io/r/rq01" ||
		!strings.HasPrefix(created.AccessLink, "https://cd-test.credenshare.io/r/rq01#1") {
		t.Fatalf("links = %s, %s", created.CollectLink, created.AccessLink)
	}
}

func TestTheCapabilitiesTypeCarriesTheOrigin(t *testing.T) {
	rec := &recorder{responses: []stubResponse{{status: 200, body: capabilitiesWithOrigin("https://cd-test.credenshare.io")}}}
	caps, err := newUnconfiguredClient(t, rec).GetCapabilities(context.Background(), nil)
	if err != nil || caps.LinkOrigin == nil || *caps.LinkOrigin != "https://cd-test.credenshare.io" {
		t.Fatalf("caps.LinkOrigin = %v, %v", caps.LinkOrigin, err)
	}
	rec = &recorder{responses: []stubResponse{{status: 200, body: capabilitiesWithOrigin(nil)}}}
	caps, err = newUnconfiguredClient(t, rec).GetCapabilities(context.Background(), nil)
	if err != nil || caps.LinkOrigin != nil {
		t.Fatalf("caps.LinkOrigin = %v, %v", caps.LinkOrigin, err)
	}
}
