package main

import (
	"log"
	"net/http"
	"os"

	"dn42-autopeer-agent/internal/api"
	"dn42-autopeer-agent/internal/runner"
)

func main() {
	addr := envOr("AGENT_LISTEN", ":8080")
	token := os.Getenv("AGENT_TOKEN")

	server := api.Server{
		Token:  token,
		Runner: runner.New(),
	}

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
