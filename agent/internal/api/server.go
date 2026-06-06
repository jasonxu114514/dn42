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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.auth(s.limit(s.status)))
	mux.HandleFunc("/v1/lg/ping", s.auth(s.limit(s.withTarget(s.Runner.Ping))))
	mux.HandleFunc("/v1/lg/mtr", s.auth(s.limit(s.withTarget(s.Runner.MTR))))
	mux.HandleFunc("/v1/lg/route", s.auth(s.limit(s.withTarget(s.Runner.Route))))
	mux.HandleFunc("/v1/peers/deploy", s.auth(s.deployPeer))
	mux.HandleFunc("/v1/peers/remove", s.auth(s.removePeer))
	return mux
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			want := "Bearer " + s.Token
			got := r.Header.Get("Authorization")
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

func (s *Server) withTarget(fn func(string) runner.Result) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, runner.Result{OK: false, Output: "method not allowed"})
			return
		}
		if contentType := r.Header.Get("Content-Type"); contentType != "" {
			mediaType, _, err := mime.ParseMediaType(contentType)
			if err != nil || !strings.EqualFold(mediaType, "application/json") {
				writeJSON(w, http.StatusUnsupportedMediaType, runner.Result{OK: false, Output: "content type must be application/json"})
				return
			}
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1024)
		var req lgRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, runner.Result{OK: false, Output: "invalid json"})
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			writeJSON(w, http.StatusBadRequest, runner.Result{OK: false, Output: "invalid json"})
			return
		}
		req.Target = strings.TrimSpace(req.Target)
		writeJSON(w, http.StatusOK, fn(req.Target))
	}
}

func (s *Server) deployPeer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, runner.DeployResult{OK: false, Output: "method not allowed"})
		return
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, runner.DeployResult{OK: false, Output: "content type must be application/json"})
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	var req runner.DeployRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, runner.DeployResult{OK: false, Output: "invalid json"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, runner.DeployResult{OK: false, Output: "invalid json"})
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
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, runner.DeployResult{OK: false, Output: "method not allowed"})
		return
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil || !strings.EqualFold(mediaType, "application/json") {
			writeJSON(w, http.StatusUnsupportedMediaType, runner.DeployResult{OK: false, Output: "content type must be application/json"})
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var req runner.RemoveRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, runner.DeployResult{OK: false, Output: "invalid json"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, runner.DeployResult{OK: false, Output: "invalid json"})
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
