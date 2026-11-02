// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

const validID = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) *server {
	t.Helper()
	return &server{dataDir: t.TempDir(), maxBytes: 1024, sourceURL: defaultSourceURL, limiter: newRateLimiter(100, time.Minute), now: time.Now}
}

func do(t *testing.T, s *server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	recorder := httptest.NewRecorder()
	s.routes().ServeHTTP(recorder, request)
	return recorder
}

func TestUploadStoresOnceAndReportsDuplicates(t *testing.T) {
	s := newTestServer(t)
	payload := ageHeaderPrefix + "abc\n"
	if got := do(t, s, http.MethodPut, "/v1/sessions/"+validID, payload).Code; got != http.StatusCreated {
		t.Fatalf("first upload: %d", got)
	}
	if got := do(t, s, http.MethodPut, "/v1/sessions/"+validID, payload).Code; got != http.StatusOK {
		t.Fatalf("duplicate upload: %d", got)
	}
	stored, err := os.ReadFile(s.sessionPath(validID))
	if err != nil || string(stored) != payload {
		t.Fatalf("stored payload mismatch: %v", err)
	}
	known := do(t, s, http.MethodPost, "/v1/sessions/known", `{"ids":["`+validID+`","ffffffffffffffffffffffffffffffff"]}`)
	if !strings.Contains(known.Body.String(), validID) || strings.Contains(known.Body.String(), "ffff") {
		t.Fatalf("known: %s", known.Body.String())
	}
}

func TestRejectsPlaintextOversizeAndBadIDs(t *testing.T) {
	s := newTestServer(t)
	if got := do(t, s, http.MethodPut, "/v1/sessions/"+validID, `{"plain":"json"}`).Code; got != http.StatusUnsupportedMediaType {
		t.Fatalf("plaintext: %d", got)
	}
	if got := do(t, s, http.MethodPut, "/v1/sessions/"+validID, ageHeaderPrefix+strings.Repeat("x", 2048)).Code; got != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: %d", got)
	}
	if got := do(t, s, http.MethodPut, "/v1/sessions/..%2Fetc", ageHeaderPrefix).Code; got != http.StatusBadRequest && got != http.StatusNotFound {
		t.Fatalf("bad id: %d", got)
	}
}

func TestConcurrentUploadsOfSameIDStoreExactlyOnce(t *testing.T) {
	s := newTestServer(t)
	codes := make(chan int, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			codes <- do(t, s, http.MethodPut, "/v1/sessions/"+validID, ageHeaderPrefix+strings.Repeat("x", i)).Code
		}(i)
	}
	created := 0
	for i := 0; i < 8; i++ {
		if <-codes == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("expected exactly one stored upload, got %d", created)
	}
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	limiter := newRateLimiter(2, time.Minute)
	now := time.Now()
	if !limiter.allow("a", now) || !limiter.allow("a", now) || limiter.allow("a", now) {
		t.Fatal("expected third request to be blocked")
	}
	if !limiter.allow("a", now.Add(2*time.Minute)) {
		t.Fatal("expected window to expire")
	}
}

func TestEveryResponseOffersTheSource(t *testing.T) {
	s := newTestServer(t)
	for _, path := range []string{"/", "/healthz", "/nope"} {
		if link := do(t, s, "GET", path, "").Header().Get("Link"); link != "<"+s.sourceURL+">; rel=\"source\"" {
			t.Fatalf("%s: Link header %q", path, link)
		}
	}
	response := do(t, s, "GET", "/source", "")
	if response.Code != http.StatusFound || response.Header().Get("Location") != s.sourceURL {
		t.Fatalf("source redirect: %d %q", response.Code, response.Header().Get("Location"))
	}
	if body := do(t, s, "GET", "/", "").Body.String(); !strings.Contains(body, s.sourceURL) {
		t.Fatalf("landing page lacks source link: %q", body)
	}
}
