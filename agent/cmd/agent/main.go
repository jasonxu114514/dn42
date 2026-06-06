package main

import (
	"log"
	"net/http"
	"os"
	"strconv"

	"dn42-autopeer-agent/internal/api"
	"dn42-autopeer-agent/internal/runner"
)

func main() {
	addr := envOr("AGENT_LISTEN", ":8080")
	token := os.Getenv("AGENT_TOKEN")
	maxConcurrency := envInt("AGENT_MAX_CONCURRENCY", 4)

	r := runner.New()
	// The agent's public key is required and served to peers (GET /v1/pubkey) so the control
	// plane can hand each peer a complete config. Fail fast on a missing/malformed key rather
	// than silently shipping peers a placeholder they cannot use.
	// agent 的公鑰為必填,並透過 GET /v1/pubkey 提供給對等端,讓控制平面能給每個對等端完整設定。
	// 金鑰缺失或格式錯誤時直接結束,避免默默地給對等端無法使用的佔位符。
	if !runner.ValidWireGuardKey(r.WireGuardPubKey) {
		log.Fatal("WIREGUARD_PUBLIC_KEY is required and must be a 44-character base64 WireGuard key")
	}

	server := api.New(token, r, maxConcurrency)

	log.Printf("dn42 autopeer agent listening on %s", addr)
	if err := http.ListenAndServe(addr, server.Handler()); err != nil {
		log.Fatal(err)
	}
}

func envOr(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func envInt(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}
