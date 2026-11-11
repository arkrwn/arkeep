// Smoke test for the TLS/TCP transport (server mode, ADR 0008): set a
// secret, read it back, confirm it round-trips, then confirm a denied
// path fails cleanly — over TLS, not the Unix socket. Run against a
// real daemon serving $ARKEEP_TLS_ADDR (see
// scripts/server-mode-smoke.sh, which generates a real self-signed CA +
// server cert and runs this for real).
//
//	Usage: ARKEEP_TLS_ADDR=127.0.0.1:PORT ARKEEP_TLS_SERVER_NAME=name \
//	  ARKEEP_TLS_CA=/path/ca.pem ARKEEP_TOKEN=<token> \
//	  [ARKEEP_TLS_CLIENT_CERT=... ARKEEP_TLS_CLIENT_KEY=...] \
//	  go run ./examples/smoke_tls [allowed-path] [denied-path]
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	arkeep "github.com/arkrwn/arkeep/sdk/go/arkeep"
)

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		fmt.Fprintf(os.Stderr, "%s must be set\n", name)
		os.Exit(1)
	}
	return v
}

func main() {
	opts := arkeep.TLSOptions{
		Addr:       mustEnv("ARKEEP_TLS_ADDR"),
		ServerName: mustEnv("ARKEEP_TLS_SERVER_NAME"),
		CACertPath: mustEnv("ARKEEP_TLS_CA"),
	}
	opts.ClientCertPath = os.Getenv("ARKEEP_TLS_CLIENT_CERT")
	opts.ClientKeyPath = os.Getenv("ARKEEP_TLS_CLIENT_KEY")
	token := mustEnv("ARKEEP_TOKEN")

	allowedPath := "sdk-smoke/go-tls"
	deniedPath := "other/denied"
	if len(os.Args) > 1 {
		allowedPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		deniedPath = os.Args[2]
	}

	client, err := arkeep.ConnectTLS(opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TLS client config error:", err)
		os.Exit(1)
	}

	value := []byte("go-sdk-tls-smoke-value")
	if err := client.Set(token, allowedPath, value); err != nil {
		fmt.Fprintln(os.Stderr, "set over TLS failed:", err)
		os.Exit(1)
	}
	got, err := client.Get(token, allowedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "get over TLS failed:", err)
		os.Exit(1)
	}
	if !bytes.Equal(got, value) {
		fmt.Fprintf(os.Stderr, "round-tripped value mismatch: got %q, want %q\n", got, value)
		os.Exit(1)
	}

	_, err = client.Get(token, deniedPath)
	var denied arkeep.DeniedError
	if !errors.As(err, &denied) {
		fmt.Fprintf(os.Stderr, "expected DeniedError for a path outside the token's prefix, got %v\n", err)
		os.Exit(1)
	}

	fmt.Println("go SDK TLS (server mode) smoke test passed")
}
