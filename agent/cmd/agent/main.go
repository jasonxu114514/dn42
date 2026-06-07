package main

import (
	"flag"
	"log"
	"net/http"

	"dn42-autopeer-agent/internal/api"
	"dn42-autopeer-agent/internal/config"
	"dn42-autopeer-agent/internal/runner"
)

func main() {
	// The config path defaults to ./config.json (relative to the working directory) and can be
	// overridden with -config; the systemd unit passes an absolute path since its cwd is /.
	// 設定檔路徑預設為 ./config.json(相對於工作目錄),可用 -config 覆寫;systemd unit 因 cwd 為 / 而傳入
	// 絕對路徑。
	configPath := flag.String("config", "config.json", "path to the agent config JSON file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal(err)
	}

	// The agent's public key is required and served to peers (GET /v1/pubkey) so the control
	// plane can hand each peer a complete config. Fail fast on a missing/malformed key rather
	// than silently shipping peers a placeholder they cannot use.
	// agent 的公鑰為必填,並透過 GET /v1/pubkey 提供給對等端,讓控制平面能給每個對等端完整設定。
	// 金鑰缺失或格式錯誤時直接結束,避免默默地給對等端無法使用的佔位符。
	if !runner.ValidWireGuardKey(cfg.WireGuardPublicKey) {
		log.Fatal("wireguard_public_key is required and must be a 44-character base64 WireGuard key")
	}

	r := runner.New(cfg)
	server := api.New(cfg.Token, r, cfg.Concurrency())

	log.Printf("dn42 autopeer agent listening on %s", cfg.Listen)
	if err := http.ListenAndServe(cfg.Listen, server.Handler()); err != nil {
		log.Fatal(err)
	}
}
