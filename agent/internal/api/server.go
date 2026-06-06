package api

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"dn42-autopeer-agent/internal/runner"
)

type Server struct {
	Token  string
	Runner runner.Runner
	sem    chan struct{}
}

// New builds a Server. When maxConcurrency > 0, looking-glass commands are bounded by a
// semaphore so a flood of public queries cannot exhaust the router's resources.
func New(token string, r runner.Runner, maxConcurrency int) *Server {
	s := &Server{Token: token, Runner: r}
	if maxConcurrency > 0 {
		s.sem = make(chan struct{}, maxConcurrency)
	}
	return s
}

type lgRequest struct {
	Target string `json:"target"`
}

type peerStatusRequest struct {
	ProtocolName string `json:"protocol_name"`
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.auth(s.limit(s.status)))
	mux.HandleFunc("/v1/lg/ping", s.auth(s.limit(s.withTarget(s.Runner.Ping))))
	mux.HandleFunc("/v1/lg/trace", s.auth(s.limit(s.withTarget(s.Runner.Trace))))
	mux.HandleFunc("/v1/lg/mtr", s.auth(s.limit(s.withTarget(s.Runner.Trace)))) // back-compat alias for trace
	mux.HandleFunc("/v1/lg/route", s.auth(s.limit(s.withTarget(s.Runner.Route))))
	mux.HandleFunc("/v1/peers/deploy", s.auth(s.deployPeer))
	mux.HandleFunc("/v1/peers/remove", s.auth(s.removePeer))
	mux.HandleFunc("/v1/peers/status", s.auth(s.limit(s.peerStatus)))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			want := "Bearer " + s.Token
			got := r.Header.Get("Authorization")
			// Constant-time compare so a caller cannot recover the token byte-by-byte
			// from response timing.
			if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
				writeJSON(w, http.StatusUnauthorized, runner.Result{OK: false, Output: "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

// limit bounds concurrent command execution. When the semaphore is full it rejects the
// request with 429 instead of queueing, so callers fail fast rather than piling up work.
func (s *Server) limit(next http.HandlerFunc) http.HandlerFunc {
	if s.sem == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.sem <- struct{}{}:
			defer func() { <-s.sem }()
			next(w, r)
		default:
			writeJSON(w, http.StatusTooManyRequests, runner.Result{OK: false, Output: "agent is busy, try again shortly"})
		}
	}
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, runner.Result{OK: false, Output: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.Runner.Status())
}

// decodeJSON enforces the shared contract for every POST body endpoint: POST only,
// Content-Type application/json (when supplied), a bounded body, and exactly one JSON
// object with no unknown fields and no trailing data. On any violation it writes the
// error response via fail (so each endpoint keeps its own Result/DeployResult shape and
// status code) and returns false; the caller just returns. dst must be a non-nil pointer.
func decodeJSON(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any, fail func(status int, message string)) bool {
	if r.Method != http.MethodPost {
		fail(http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			fail(http.StatusUnsupportedMediaType, "content type must be application/json")
			return false
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		fail(http.StatusBadRequest, "invalid json")
		return false
	}
	// A second decode must hit EOF; anything else means trailing data after the object.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		fail(http.StatusBadRequest, "invalid json")
		return false
	}
	return true
}

func (s *Server) withTarget(fn func(string) runner.Result) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fail := func(status int, message string) {
			writeJSON(w, status, runner.Result{OK: false, Output: message})
		}
		var req lgRequest
		if !decodeJSON(w, r, 1024, &req, fail) {
			return
		}
		writeJSON(w, http.StatusOK, fn(strings.TrimSpace(req.Target)))
	}
}

func (s *Server) peerStatus(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, message string) {
		writeJSON(w, status, runner.Result{OK: false, Output: message})
	}
	var req peerStatusRequest
	if !decodeJSON(w, r, 1024, &req, fail) {
		return
	}
	writeJSON(w, http.StatusOK, s.Runner.PeerStatus(req.ProtocolName))
}

func (s *Server) deployPeer(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, message string) {
		writeJSON(w, status, runner.DeployResult{OK: false, Output: message})
	}
	var req runner.DeployRequest
	if !decodeJSON(w, r, 64*1024, &req, fail) {
		return
	}
	result := s.Runner.DeployPeer(req)
	if !result.OK {
		writeJSON(w, http.StatusBadRequest, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) removePeer(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, message string) {
		writeJSON(w, status, runner.DeployResult{OK: false, Output: message})
	}
	var req runner.RemoveRequest
	if !decodeJSON(w, r, 1024, &req, fail) {
		return
	}
	result := s.Runner.RemovePeer(req)
	if !result.OK {
		writeJSON(w, http.StatusBadRequest, result)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
