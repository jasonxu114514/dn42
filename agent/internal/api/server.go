package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"dn42-autopeer-agent/internal/runner"
)

type Server struct {
	Runner   runner.Runner
	sem      chan struct{}
	deployMu sync.Mutex
}

// New builds the command dispatcher. When maxConcurrency > 0, looking-glass commands are
// bounded by a semaphore so public queries cannot exhaust the router's resources.
func New(r runner.Runner, maxConcurrency int) *Server {
	s := &Server{Runner: r}
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

type peerStatusResponse struct {
	OK        bool   `json:"ok"`
	Output    string `json:"output"`
	WireGuard string `json:"wireguard"`
}

type pubkeyResponse struct {
	PublicKey string `json:"public_key"`
}

// Command executes one backend websocket request and returns a JSON-serialisable response.
func (s *Server) Command(command string, payload json.RawMessage) (any, error) {
	switch command {
	case "pubkey":
		return pubkeyResponse{PublicKey: s.Runner.WireGuardPubKey}, nil
	case "lg.ping":
		return s.targetCommand(payload, s.Runner.Ping)
	case "lg.trace":
		return s.targetCommand(payload, s.Runner.Trace)
	case "lg.mtr":
		return s.targetCommand(payload, s.Runner.Mtr)
	case "lg.route":
		return s.targetCommand(payload, s.Runner.Route)
	case "peers.status":
		var req peerStatusRequest
		if err := decodeCommandPayload(payload, &req); err != nil {
			return nil, err
		}
		return s.limitedPeerStatus(req.ProtocolName), nil
	case "peers.deploy":
		var req runner.DeployRequest
		if err := decodeCommandPayload(payload, &req); err != nil {
			return nil, err
		}
		return s.deployPeer(req), nil
	case "peers.remove":
		var req runner.RemoveRequest
		if err := decodeCommandPayload(payload, &req); err != nil {
			return nil, err
		}
		return s.removePeer(req), nil
	default:
		return nil, fmt.Errorf("unknown command %q", command)
	}
}

func (s *Server) deployPeer(req runner.DeployRequest) runner.DeployResult {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	return s.Runner.DeployPeer(req)
}

func (s *Server) removePeer(req runner.RemoveRequest) runner.DeployResult {
	s.deployMu.Lock()
	defer s.deployMu.Unlock()
	return s.Runner.RemovePeer(req)
}

func (s *Server) tryAcquire() (func(), bool) {
	if s.sem == nil {
		return func() {}, true
	}
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, true
	default:
		return nil, false
	}
}

func (s *Server) limitedResult(fn func() runner.Result) runner.Result {
	release, ok := s.tryAcquire()
	if !ok {
		return runner.Result{OK: false, Output: "agent is busy, try again shortly"}
	}
	defer release()
	return fn()
}

func (s *Server) limitedPeerStatus(protocolName string) peerStatusResponse {
	release, ok := s.tryAcquire()
	if !ok {
		return peerStatusResponse{OK: false, Output: "agent is busy, try again shortly"}
	}
	defer release()
	return s.peerStatusForProtocol(protocolName)
}

func (s *Server) targetCommand(
	payload json.RawMessage,
	fn func(string) runner.Result,
) (runner.Result, error) {
	var req lgRequest
	if err := decodeCommandPayload(payload, &req); err != nil {
		return runner.Result{}, err
	}
	return s.limitedResult(func() runner.Result { return fn(strings.TrimSpace(req.Target)) }), nil
}

func decodeCommandPayload(payload json.RawMessage, dst any) error {
	if trimmed := bytes.TrimSpace(payload); len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		payload = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return errors.New("invalid json")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("invalid json")
	}
	return nil
}

func (s *Server) peerStatusForProtocol(protocolName string) peerStatusResponse {
	bird := s.Runner.PeerStatus(protocolName)
	wg := s.Runner.PeerWireGuard(protocolName)
	return peerStatusResponse{OK: bird.OK, Output: bird.Output, WireGuard: wg.Output}
}
