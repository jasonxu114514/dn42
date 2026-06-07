package main

import (
	"context"
	"flag"
	"log"

	"dn42-autopeer-agent/internal/api"
	"dn42-autopeer-agent/internal/backend"
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

	// The agent's public key is required and reported to the control plane so each peer can
	// receive a complete config. Fail fast on a missing/malformed key rather than silently
	// shipping peers a placeholder they cannot use.
	// agent 的公鑰為必填,並回報給控制平面,讓每個對等端都能取得完整設定。
	// 金鑰缺失或格式錯誤時直接結束,避免默默地給對等端無法使用的佔位符。
	if !runner.ValidWireGuardKey(cfg.WireGuardPublicKey) {
		log.Fatal("wireguard_public_key is required and must be a 44-character base64 WireGuard key")
	}
	if cfg.BackendWSURL == "" {
		log.Fatal("backend_wss_url is required")
	}
	if cfg.Name == "" {
		log.Fatal("name is required when backend_wss_url is set")
	}

	r := runner.New(cfg)
	server := api.New(r, cfg.Concurrency())
	client := backend.New(cfg, server)
	client.Run(context.Background())
}
