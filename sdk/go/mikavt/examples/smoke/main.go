// Smoke test: set a secret, read it back, confirm it round-trips, then
// confirm a denied path fails cleanly. Run against a real mikavtd (see
// scripts/sdk-smoke.sh, which bootstraps one and runs this for real —
// this is not a mocked test).
//
// Usage: MIKAVT_SOCKET=/path/to.sock MIKAVT_TOKEN=<token> go run ./examples/smoke [allowed-path] [denied-path]
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	mikavt "github.com/arkrwn/mikavt/sdk/go/mikavt"
)

func main() {
	socket := os.Getenv("MIKAVT_SOCKET")
	token := os.Getenv("MIKAVT_TOKEN")
	if socket == "" || token == "" {
		fmt.Fprintln(os.Stderr, "MIKAVT_SOCKET and MIKAVT_TOKEN must be set")
		os.Exit(1)
	}

	allowedPath := "sdk-smoke/go"
	deniedPath := "other/denied"
	if len(os.Args) > 1 {
		allowedPath = os.Args[1]
	}
	if len(os.Args) > 2 {
		deniedPath = os.Args[2]
	}

	client := mikavt.Connect(socket)
	value := []byte("go-sdk-smoke-value")

	if err := client.Set(token, allowedPath, value); err != nil {
		fmt.Fprintln(os.Stderr, "set failed:", err)
		os.Exit(1)
	}

	got, err := client.Get(token, allowedPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "get failed:", err)
		os.Exit(1)
	}
	if !bytes.Equal(got, value) {
		fmt.Fprintf(os.Stderr, "round-tripped value mismatch: got %q, want %q\n", got, value)
		os.Exit(1)
	}

	_, err = client.Get(token, deniedPath)
	var denied mikavt.DeniedError
	if !errors.As(err, &denied) {
		fmt.Fprintf(os.Stderr, "expected DeniedError for a path outside the token's prefix, got %v\n", err)
		os.Exit(1)
	}

	fmt.Println("go SDK smoke test passed")
}
