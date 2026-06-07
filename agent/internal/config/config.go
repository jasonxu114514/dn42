// Package config loads the agent's runtime configuration from a single JSON file. It replaces the
// former environment-variable configuration: every setting — including the bearer token and the
// WireGuard private key — now lives in this file, so the file must be root-owned and chmod 0600.
// config 套件從單一 JSON 檔載入 agent 的執行設定，取代原本的環境變數設定:所有設定(含 bearer token
// 與 WireGuard 私鑰)都放在此檔,故檔案須由 root 擁有且權限為 0600。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	defaultListen         = ":8080"
	defaultMaxConcurrency = 4
	defaultTimeoutSeconds = 12
	defaultBirdcPath      = "birdc"
	defaultPingPath       = "ping"
	defaultTraceroutePath = "traceroute"
	defaultWgQuickPath    = "wg-quick"
	defaultWireGuardDir   = "/etc/wireguard"
	defaultBirdPeerDir    = "/etc/bird/peers"
)

// Config is the agent's full runtime configuration. Field defaults are applied by applyDefaults
// after decoding, so a minimal file need only set wireguard_public_key (required) and usually token.
// Config 為 agent 的完整執行設定。欄位預設值於解碼後由 applyDefaults 套用,因此最小設定檔只需給定
// wireguard_public_key(必填),通常再加上 token 即可。
type Config struct {
	Listen string `json:"listen"`
	Token  string `json:"token"`
	// MaxConcurrency bounds concurrent looking-glass commands. A pointer distinguishes "unset"
	// (nil -> default 4) from an explicit 0, which disables the cap entirely; a negative value
	// falls back to the default, mirroring the previous env parsing.
	// MaxConcurrency 限制併發的 looking-glass 指令數。用指標區分「未設定」(nil → 預設 4)與明確的 0
	// (停用上限);負數則退回預設,沿用先前環境變數的解析語意。
	MaxConcurrency *int `json:"max_concurrency"`
	// CommandTimeoutSeconds bounds each external command (ping/traceroute/birdc/wg-quick). Zero or
	// negative falls back to the default. This was previously hard-coded at 12 seconds.
	// CommandTimeoutSeconds 限制每個外部命令(ping/traceroute/birdc/wg-quick)的執行時間。0 或負數退回
	// 預設值。此值原本寫死為 12 秒。
	CommandTimeoutSeconds int `json:"command_timeout_seconds"`

	BirdcPath      string `json:"birdc_path"`
	PingPath       string `json:"ping_path"`
	TraceroutePath string `json:"traceroute_path"`
	WgQuickPath    string `json:"wg_quick_path"`

	WireGuardPeerDir string `json:"wireguard_peer_dir"`
	BirdPeerDir      string `json:"bird_peer_dir"`
	DeployReloadCmd  string `json:"deploy_reload_cmd"`

	WireGuardPrivateKey string `json:"wireguard_private_key"`
	WireGuardPublicKey  string `json:"wireguard_public_key"`
}

// Load reads and parses the config file at path. Unknown JSON keys are rejected so a typo in the
// config surfaces as an error instead of being silently ignored. Defaults are applied before return;
// the caller still validates wireguard_public_key (its required shape lives in the runner package).
// Load 讀取並解析 path 的設定檔。未知的 JSON 鍵會被拒絕,使設定檔的拼字錯誤直接報錯而非默默忽略。
// 回傳前會套用預設值;呼叫端仍須驗證 wireguard_public_key(其必要格式定義於 runner 套件)。
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var cfg Config
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

// applyDefaults trims string fields and fills empty values with their defaults. It mirrors the
// trimming the previous env-based loader performed (token, keys, reload command, tool paths).
// applyDefaults 修剪字串欄位並以預設值填補空值。其修剪行為與先前以環境變數為基礎的載入器一致
// (token、金鑰、reload 指令、工具路徑)。
func (c *Config) applyDefaults() {
	c.Listen = orDefault(c.Listen, defaultListen)
	c.Token = strings.TrimSpace(c.Token)
	if c.CommandTimeoutSeconds <= 0 {
		c.CommandTimeoutSeconds = defaultTimeoutSeconds
	}

	c.BirdcPath = orDefault(c.BirdcPath, defaultBirdcPath)
	c.PingPath = orDefault(c.PingPath, defaultPingPath)
	c.TraceroutePath = orDefault(c.TraceroutePath, defaultTraceroutePath)
	c.WgQuickPath = orDefault(c.WgQuickPath, defaultWgQuickPath)

	c.WireGuardPeerDir = orDefault(c.WireGuardPeerDir, defaultWireGuardDir)
	c.BirdPeerDir = orDefault(c.BirdPeerDir, defaultBirdPeerDir)
	c.DeployReloadCmd = strings.TrimSpace(c.DeployReloadCmd)

	c.WireGuardPrivateKey = strings.TrimSpace(c.WireGuardPrivateKey)
	c.WireGuardPublicKey = strings.TrimSpace(c.WireGuardPublicKey)
}

// Concurrency resolves the looking-glass concurrency cap: nil or a negative value yields the
// default, while a configured 0 means "unbounded" and is passed through unchanged.
// Concurrency 解析 looking-glass 併發上限:nil 或負值回傳預設,設定為 0 代表「不限制」並原樣傳遞。
func (c Config) Concurrency() int {
	if c.MaxConcurrency == nil || *c.MaxConcurrency < 0 {
		return defaultMaxConcurrency
	}
	return *c.MaxConcurrency
}

// Timeout returns the per-command timeout as a duration.
// Timeout 以 time.Duration 回傳每個命令的逾時。
func (c Config) Timeout() time.Duration {
	return time.Duration(c.CommandTimeoutSeconds) * time.Second
}

func orDefault(value, fallback string) string {
	if trimmed := strings.TrimSpace(value); trimmed != "" {
		return trimmed
	}
	return fallback
}
