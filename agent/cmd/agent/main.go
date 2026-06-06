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

	server := api.New(token, runner.New(), maxConcurrency)

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
