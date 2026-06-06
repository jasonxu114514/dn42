package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"dn42-autopeer-agent/internal/runner"
)

type Server struct {
	Token  string
	Runner runner.Runner
}

type lgRequest struct {
	Target string `json:"target"`
}

func (s Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", s.auth(s.status))
	mux.HandleFunc("/v1/lg/ping", s.auth(s.withTarget(s.Runner.Ping)))
	mux.HandleFunc("/v1/lg/mtr", s.auth(s.withTarget(s.Runner.MTR)))
	mux.HandleFunc("/v1/lg/route", s.auth(s.withTarget(s.Runner.Route)))
	return mux
}

func (s Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			want := "Bearer " + s.Token
			if r.Header.Get("Authorization") != want {
				writeJSON(w, http.StatusUnauthorized, runner.Result{OK: false, Output: "unauthorized"})
				return
			}
		}
		next(w, r)
	}
}

func (s Server) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, runner.Result{OK: false, Output: "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, s.Runner.Status())
}

func (s Server) withTarget(fn func(string) runner.Result) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, runner.Result{OK: false, Output: "method not allowed"})
			return
		}
		var req lgRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, runner.Result{OK: false, Output: "invalid json"})
			return
		}
		req.Target = strings.TrimSpace(req.Target)
		writeJSON(w, http.StatusOK, fn(req.Target))
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
