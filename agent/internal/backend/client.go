package backend

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"dn42-autopeer-agent/internal/api"
	"dn42-autopeer-agent/internal/config"
	"dn42-autopeer-agent/internal/runner"
)

const (
	defaultReconnectDelay = 5 * time.Second
	heartbeatInterval     = 20 * time.Second
	// statusSampleInterval bounds how often the heartbeat actually shells out to wg/birdc. Every
	// heartbeat still ships a full system snapshot, but the WireGuard/BIRD command output is
	// re-sampled at most this often and reused in between, so liveness stays at heartbeatInterval
	// while subprocess spawns drop ~3x.
	statusSampleInterval = 60 * time.Second
	maxFramePayload      = 1 << 20
	maxStatusOutput      = 65536
	websocketGUID        = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

type Client struct {
	cfg       config.Config
	server    *api.Server
	metricsMu sync.Mutex
	lastUsage usageSample

	statusMu   sync.Mutex
	lastStatus statusSample
}

type requestEnvelope struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Command string          `json:"command"`
	Payload json.RawMessage `json:"payload"`
}

type responseEnvelope struct {
	Type   string `json:"type"`
	ID     string `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

type heartbeatEnvelope struct {
	Type      string       `json:"type"`
	PublicKey string       `json:"public_key"`
	System    systemStatus `json:"system"`
}

type systemStatus struct {
	Hostname                string   `json:"hostname"`
	OS                      string   `json:"os"`
	Arch                    string   `json:"arch"`
	UptimeSeconds           int64    `json:"uptime_seconds,omitempty"`
	Load1                   float64  `json:"load_1,omitempty"`
	Load5                   float64  `json:"load_5,omitempty"`
	Load15                  float64  `json:"load_15,omitempty"`
	CPUPercent              *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent           *float64 `json:"memory_percent,omitempty"`
	MemoryUsedBytes         int64    `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes        int64    `json:"memory_total_bytes,omitempty"`
	NetworkRxBytesPerSecond *float64 `json:"network_rx_bytes_per_second,omitempty"`
	NetworkTxBytesPerSecond *float64 `json:"network_tx_bytes_per_second,omitempty"`
	Goroutines              int      `json:"goroutines"`
	WireGuard               status   `json:"wireguard"`
	Bird                    status   `json:"bird"`
}

type status struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

type cpuSample struct {
	total uint64
	idle  uint64
}

type networkSample struct {
	rxBytes uint64
	txBytes uint64
}

type usageSample struct {
	at time.Time

	cpu   cpuSample
	cpuOK bool

	network   networkSample
	networkOK bool
}

type resourceUsage struct {
	CPUPercent              *float64
	MemoryPercent           *float64
	MemoryUsedBytes         int64
	MemoryTotalBytes        int64
	NetworkRxBytesPerSecond *float64
	NetworkTxBytesPerSecond *float64
}

// statusSample caches the most recent WireGuard/BIRD command output so heartbeats can reuse it
// between samples (see statusSampleInterval).
type statusSample struct {
	at        time.Time
	wireguard status
	bird      status
	valid     bool
}

func New(cfg config.Config, server *api.Server) *Client {
	return &Client{cfg: cfg, server: server}
}

func (c *Client) Run(ctx context.Context) {
	if c.cfg.BackendWSURL == "" {
		return
	}
	for {
		if err := c.runOnce(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("backend websocket disconnected: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(defaultReconnectDelay):
		}
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	endpoint, err := c.endpoint()
	if err != nil {
		return err
	}
	conn, err := dialWebSocket(ctx, endpoint, c.cfg.Token)
	if err != nil {
		return err
	}
	defer conn.Close()
	log.Printf("connected to backend websocket %s", endpoint)

	if err := conn.WriteJSON(c.heartbeat("hello")); err != nil {
		return err
	}

	heartbeatErr := make(chan error, 1)
	go c.heartbeatLoop(ctx, conn, heartbeatErr)

	for {
		select {
		case err := <-heartbeatErr:
			return err
		default:
		}
		var req requestEnvelope
		if err := conn.ReadJSON(&req); err != nil {
			return err
		}
		if req.Type != "request" || req.ID == "" {
			continue
		}
		go c.handleRequest(conn, req)
	}
}

func (c *Client) endpoint() (string, error) {
	if c.cfg.Name == "" {
		return "", errors.New("name is required when backend_wss_url is set")
	}
	u, err := url.Parse(c.cfg.BackendWSURL)
	if err != nil {
		return "", err
	}
	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	case "http":
		u.Scheme = "ws"
	case "ws", "wss":
	default:
		return "", fmt.Errorf("backend_wss_url must use ws, wss, http, or https")
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/api/agents/ws"
	}
	q := u.Query()
	if q.Get("name") == "" {
		q.Set("name", c.cfg.Name)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (c *Client) handleRequest(conn *wsConn, req requestEnvelope) {
	result, err := c.server.Command(req.Command, req.Payload)
	resp := responseEnvelope{Type: "response", ID: req.ID, Result: result}
	if err != nil {
		resp.Result = nil
		resp.Error = err.Error()
	}
	if err := conn.WriteJSON(resp); err != nil {
		log.Printf("write websocket response failed: %v", err)
	}
}

func (c *Client) heartbeatLoop(ctx context.Context, conn *wsConn, errs chan<- error) {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = conn.Close()
			errs <- ctx.Err()
			return
		case <-ticker.C:
			if err := conn.WriteJSON(c.heartbeat("heartbeat")); err != nil {
				_ = conn.Close()
				errs <- err
				return
			}
		}
	}
}

func (c *Client) heartbeat(kind string) heartbeatEnvelope {
	return heartbeatEnvelope{
		Type:      kind,
		PublicKey: c.cfg.WireGuardPublicKey,
		System:    c.collectSystemStatus(),
	}
}

func (c *Client) collectSystemStatus() systemStatus {
	hostname, _ := os.Hostname()
	load1, load5, load15 := loadAverage()
	usage := c.collectResourceUsage()
	wireguard, bird := c.commandStatuses()
	return systemStatus{
		Hostname:                hostname,
		OS:                      runtime.GOOS,
		Arch:                    runtime.GOARCH,
		UptimeSeconds:           uptimeSeconds(),
		Load1:                   load1,
		Load5:                   load5,
		Load15:                  load15,
		CPUPercent:              usage.CPUPercent,
		MemoryPercent:           usage.MemoryPercent,
		MemoryUsedBytes:         usage.MemoryUsedBytes,
		MemoryTotalBytes:        usage.MemoryTotalBytes,
		NetworkRxBytesPerSecond: usage.NetworkRxBytesPerSecond,
		NetworkTxBytesPerSecond: usage.NetworkTxBytesPerSecond,
		Goroutines:              runtime.NumGoroutine(),
		WireGuard:               wireguard,
		Bird:                    bird,
	}
}

// commandStatuses returns the WireGuard/BIRD status, re-running the underlying wg/birdc commands
// at most once per statusSampleInterval and reusing the cached result for the heartbeats in
// between. Heartbeats are serial, so the lock is held across the commands without contention.
func (c *Client) commandStatuses() (status, status) {
	now := time.Now()
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	if c.lastStatus.valid && now.Sub(c.lastStatus.at) < statusSampleInterval {
		return c.lastStatus.wireguard, c.lastStatus.bird
	}
	c.lastStatus = statusSample{
		at:        now,
		wireguard: commandStatus(c.server.Runner.WireGuardStatus()),
		bird:      commandStatus(c.server.Runner.BirdStatus()),
		valid:     true,
	}
	return c.lastStatus.wireguard, c.lastStatus.bird
}

func (c *Client) collectResourceUsage() resourceUsage {
	usage := resourceUsage{}
	if memoryPercent, usedBytes, totalBytes, ok := memoryUsage(); ok {
		usage.MemoryPercent = &memoryPercent
		usage.MemoryUsedBytes = usedBytes
		usage.MemoryTotalBytes = totalBytes
	}

	now := time.Now()
	cpu, cpuOK := readCPUSample()
	network, networkOK := readNetworkSample()

	c.metricsMu.Lock()
	defer c.metricsMu.Unlock()

	previous := c.lastUsage
	c.lastUsage = usageSample{
		at:        now,
		cpu:       cpu,
		cpuOK:     cpuOK,
		network:   network,
		networkOK: networkOK,
	}
	if previous.at.IsZero() {
		return usage
	}

	elapsed := now.Sub(previous.at).Seconds()
	if elapsed <= 0 {
		return usage
	}
	if cpuOK && previous.cpuOK && cpu.total > previous.cpu.total {
		totalDelta := cpu.total - previous.cpu.total
		idleDelta := cpu.idle - previous.cpu.idle
		if totalDelta > 0 && idleDelta <= totalDelta {
			cpuPercent := (float64(totalDelta-idleDelta) / float64(totalDelta)) * 100
			usage.CPUPercent = &cpuPercent
		}
	}
	if networkOK && previous.networkOK {
		if network.rxBytes >= previous.network.rxBytes {
			rx := float64(network.rxBytes-previous.network.rxBytes) / elapsed
			usage.NetworkRxBytesPerSecond = &rx
		}
		if network.txBytes >= previous.network.txBytes {
			tx := float64(network.txBytes-previous.network.txBytes) / elapsed
			usage.NetworkTxBytesPerSecond = &tx
		}
	}
	return usage
}

func commandStatus(result runner.Result) status {
	output := result.Output
	if len(output) > maxStatusOutput {
		output = output[:maxStatusOutput] + "\n[truncated]"
	}
	return status{OK: result.OK, Output: output}
}

func uptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(value)
}

func loadAverage() (float64, float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	load := func(index int) float64 {
		value, err := strconv.ParseFloat(fields[index], 64)
		if err != nil {
			return 0
		}
		return value
	}
	return load(0), load(1), load(2)
}

func readCPUSample() (cpuSample, bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return cpuSample{}, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	var values []uint64
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSample{}, false
		}
		values = append(values, value)
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuSample{total: total, idle: idle}, total > 0
}

func memoryUsage() (float64, int64, int64, bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, 0, false
	}
	var totalKB int64
	var availableKB int64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			totalKB = value
		case "MemAvailable":
			availableKB = value
		}
	}
	if totalKB <= 0 || availableKB < 0 {
		return 0, 0, 0, false
	}
	usedKB := totalKB - availableKB
	if usedKB < 0 {
		usedKB = 0
	}
	percent := (float64(usedKB) / float64(totalKB)) * 100
	return percent, usedKB * 1024, totalKB * 1024, true
}

func readNetworkSample() (networkSample, bool) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return networkSample{}, false
	}
	var sample networkSample
	var found bool
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		iface := strings.TrimSpace(parts[0])
		if iface == "" || iface == "lo" {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rxBytes, rxErr := strconv.ParseUint(fields[0], 10, 64)
		txBytes, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr != nil || txErr != nil {
			continue
		}
		sample.rxBytes += rxBytes
		sample.txBytes += txBytes
		found = true
	}
	return sample, found
}

type wsConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	writeMu sync.Mutex
}

func dialWebSocket(ctx context.Context, rawURL string, token string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	address := net.JoinHostPort(u.Hostname(), websocketPort(u))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var conn net.Conn
	switch u.Scheme {
	case "wss":
		conn, err = tls.DialWithDialer(
			dialer,
			"tcp",
			address,
			&tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()},
		)
	case "ws":
		conn, err = dialer.DialContext(ctx, "tcp", address)
	default:
		err = fmt.Errorf("unsupported websocket scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, err
	}

	key, err := websocketKey()
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := writeHandshake(conn, u, key, token); err != nil {
		_ = conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := verifyHandshake(resp, key); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return &wsConn{conn: conn, reader: reader}, nil
}

func websocketPort(u *url.URL) string {
	if port := u.Port(); port != "" {
		return port
	}
	if u.Scheme == "wss" {
		return "443"
	}
	return "80"
}

func websocketKey() (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(nonce), nil
}

func writeHandshake(conn net.Conn, u *url.URL, key string, token string) error {
	requestURI := u.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "GET %s HTTP/1.1\r\n", requestURI)
	fmt.Fprintf(&buf, "Host: %s\r\n", u.Host)
	fmt.Fprintf(&buf, "Upgrade: websocket\r\n")
	fmt.Fprintf(&buf, "Connection: Upgrade\r\n")
	fmt.Fprintf(&buf, "Sec-WebSocket-Key: %s\r\n", key)
	fmt.Fprintf(&buf, "Sec-WebSocket-Version: 13\r\n")
	fmt.Fprintf(&buf, "User-Agent: dn42-autopeer-agent\r\n")
	if token != "" {
		fmt.Fprintf(&buf, "Authorization: Bearer %s\r\n", token)
	}
	fmt.Fprintf(&buf, "\r\n")
	_, err := conn.Write(buf.Bytes())
	return err
}

func verifyHandshake(resp *http.Response, key string) error {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket upgrade failed with HTTP %s", resp.Status)
	}
	if !headerHasToken(resp.Header, "Upgrade", "websocket") {
		return errors.New("websocket upgrade response missing Upgrade: websocket")
	}
	if !headerHasToken(resp.Header, "Connection", "upgrade") {
		return errors.New("websocket upgrade response missing Connection: upgrade")
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), websocketAccept(key); got != want {
		return errors.New("websocket upgrade response has invalid accept key")
	}
	return nil
}

func headerHasToken(header http.Header, key string, token string) bool {
	for _, value := range header.Values(key) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func websocketAccept(key string) string {
	sum := sha1.Sum([]byte(key + websocketGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (c *wsConn) ReadJSON(dst any) error {
	for {
		opcode, payload, err := c.readFrame()
		if err != nil {
			return err
		}
		switch opcode {
		case 1:
			return json.Unmarshal(payload, dst)
		case 8:
			_ = c.writeFrame(8, nil)
			return io.EOF
		case 9:
			_ = c.writeFrame(10, payload)
		case 10:
			continue
		default:
			return fmt.Errorf("unsupported websocket opcode %d", opcode)
		}
	}
}

func (c *wsConn) WriteJSON(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.writeFrame(1, payload)
}

func (c *wsConn) Close() error {
	_ = c.writeFrame(8, nil)
	return c.conn.Close()
}

func (c *wsConn) readFrame() (byte, []byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(c.reader, header[:]); err != nil {
		return 0, nil, err
	}
	fin := header[0]&0x80 != 0
	opcode := header[0] & 0x0f
	masked := header[1]&0x80 != 0
	length := uint64(header[1] & 0x7f)
	switch length {
	case 126:
		var extended [2]byte
		if _, err := io.ReadFull(c.reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(extended[:]))
	case 127:
		var extended [8]byte
		if _, err := io.ReadFull(c.reader, extended[:]); err != nil {
			return 0, nil, err
		}
		length = binary.BigEndian.Uint64(extended[:])
	}
	if !fin {
		return 0, nil, errors.New("fragmented websocket frames are not supported")
	}
	if length > maxFramePayload {
		return 0, nil, errors.New("websocket frame is too large")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(c.reader, mask[:]); err != nil {
			return 0, nil, err
		}
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.reader, payload); err != nil {
		return 0, nil, err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return opcode, payload, nil
}

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var buf bytes.Buffer
	buf.WriteByte(0x80 | opcode)
	length := len(payload)
	switch {
	case length < 126:
		buf.WriteByte(0x80 | byte(length))
	case length <= 65535:
		buf.WriteByte(0x80 | 126)
		var extended [2]byte
		binary.BigEndian.PutUint16(extended[:], uint16(length))
		buf.Write(extended[:])
	default:
		buf.WriteByte(0x80 | 127)
		var extended [8]byte
		binary.BigEndian.PutUint64(extended[:], uint64(length))
		buf.Write(extended[:])
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	buf.Write(mask[:])
	for i, b := range payload {
		buf.WriteByte(b ^ mask[i%4])
	}
	_, err := c.conn.Write(buf.Bytes())
	return err
}
