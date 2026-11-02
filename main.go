// SPDX-License-Identifier: AGPL-3.0-only

// Command plektra-datadrop accepts end-to-end encrypted typing-training sessions.
//
// The server only stores age ciphertext; it cannot read session contents. Client IP
// addresses are used transiently for rate limiting and are never written to disk or logs.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const ageHeaderPrefix = "age-encryption.org/v1\n-> X25519 "

var (
	sessionIDPattern  = regexp.MustCompile(`^[0-9a-f]{32,64}$`)
	appVersionPattern = regexp.MustCompile(`^[0-9A-Za-z._+-]{1,64}$`)
)

type server struct {
	publish  sync.Mutex // serialises the exists-check and publication of a session
	dataDir  string
	maxBytes int64
	// sourceURL is offered on every response (AGPL-3.0 section 13).
	sourceURL string
	limiter   *rateLimiter
	now       func() time.Time
}

type metadata struct {
	ReceivedAt string `json:"receivedAt"`
	Bytes      int    `json:"bytes"`
	AppVersion string `json:"appVersion,omitempty"`
}

func main() {
	listen := flag.String("listen", envOr("LISTEN", "127.0.0.1:8080"), "listen address")
	dataDir := flag.String("data", envOr("DATA_DIR", "./data"), "storage directory")
	maxBytes := flag.Int64("max-bytes", 8<<20, "maximum ciphertext size per session")
	sourceURL := flag.String("source-url", envOr("SOURCE_URL", defaultSourceURL), "public repository of the running source (AGPL-3.0 section 13)")
	flag.Parse()
	if err := os.MkdirAll(filepath.Join(*dataDir, "sessions"), 0o750); err != nil {
		log.Fatal(err)
	}
	s := &server{dataDir: *dataDir, maxBytes: *maxBytes, sourceURL: *sourceURL, limiter: newRateLimiter(60, 10*time.Minute), now: time.Now}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("listening on %s, storing in %s", *listen, *dataDir)
	log.Fatal(httpServer.ListenAndServe())
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// defaultSourceURL is where users interacting with this server can obtain its source,
// as required by section 13 of the GNU AGPL. Deployments of modified versions must
// point -source-url at their own published source.
const defaultSourceURL = "https://github.com/pkb-rocks/plektra-datadrop"

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "Plektra datadrop: receives encrypted, opt-in typing-training sessions from the Plektra app.\n"+
			"Free software under the GNU AGPL v3. Source code: "+s.sourceURL+"\n")
	})
	mux.HandleFunc("GET /source", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.sourceURL, http.StatusFound)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /v1/sessions/known", s.handleKnown)
	mux.HandleFunc("PUT /v1/sessions/{id}", s.handleUpload)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Every response offers the corresponding source.
		w.Header().Set("Link", "<"+s.sourceURL+">; rel=\"source\"")
		mux.ServeHTTP(w, r)
	})
}

func (s *server) sessionPath(id string) string {
	return filepath.Join(s.dataDir, "sessions", id[:2], id+".age")
}

func (s *server) exists(id string) bool {
	_, err := os.Stat(s.sessionPath(id))
	return err == nil
}

func (s *server) handleKnown(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientKey(r), s.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	var request struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&request); err != nil || len(request.IDs) > 1000 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request"})
		return
	}
	known := []string{}
	for _, id := range request.IDs {
		if sessionIDPattern.MatchString(id) && s.exists(id) {
			known = append(known, id)
		}
	}
	writeJSON(w, http.StatusOK, map[string][]string{"known": known})
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !sessionIDPattern.MatchString(id) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid session id"})
		return
	}
	if s.exists(id) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "exists"})
		return
	}
	if !s.limiter.allow(clientKey(r), s.now()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "too large"})
		} else {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read failed"})
		}
		return
	}
	if !bytes.HasPrefix(body, []byte(ageHeaderPrefix)) {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "expected age ciphertext"})
		return
	}
	path := s.sessionPath(id)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage failed"})
		return
	}
	meta := metadata{ReceivedAt: s.now().UTC().Format(time.RFC3339), Bytes: len(body)}
	if version := r.Header.Get("X-Plektra-Version"); appVersionPattern.MatchString(version) {
		meta.AppVersion = version
	}
	metaBytes, _ := json.Marshal(meta)
	s.publish.Lock()
	defer s.publish.Unlock()
	// A concurrent upload of the same id may have won while this body was being read.
	if s.exists(id) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "exists"})
		return
	}
	if err := writeAtomic(strings.TrimSuffix(path, ".age")+".json", metaBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage failed"})
		return
	}
	// The ciphertext is published last and never replaces an existing file; its presence
	// marks a complete session.
	if err := writeNew(path, body); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage failed"})
		return
	}
	log.Printf("stored session (%d bytes)", len(body))
	writeJSON(w, http.StatusCreated, map[string]string{"status": "stored"})
}

func writeAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// writeNew writes content to a temporary file and links it into place; it fails instead of
// overwriting an existing file.
func writeNew(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Link(tmp.Name(), path)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

// clientKey identifies a client for rate limiting. Behind a reverse proxy on localhost the
// proxy must set X-Forwarded-For; the value is only kept in memory.
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
			return forwarded
		}
	}
	return host
}

type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: map[string][]time.Time{}}
}

func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	recent := l.hits[key][:0]
	for _, hit := range l.hits[key] {
		if now.Sub(hit) < l.window {
			recent = append(recent, hit)
		}
	}
	if len(recent) >= l.limit {
		l.hits[key] = recent
		return false
	}
	l.hits[key] = append(recent, now)
	if len(l.hits) > 10000 {
		for key, hits := range l.hits {
			if len(hits) == 0 || now.Sub(hits[len(hits)-1]) >= l.window {
				delete(l.hits, key)
			}
		}
	}
	return true
}
