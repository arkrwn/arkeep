# Sample integration: Go

Module: [`sdk/go/mikavt`](../../sdk/go/mikavt) — standard library only.

```bash
go get github.com/arkrwn/mikavt/sdk/go/mikavt
```

```go
package main

import (
	"errors"
	"fmt"
	"os"

	mikavt "github.com/arkrwn/mikavt/sdk/go/mikavt"
)

func main() {
	client := mikavt.Connect(os.Getenv("MIKAVT_SOCKET"))
	token := os.Getenv("MIKAVT_TOKEN")

	if err := client.Set(token, "myapp/DB_PASSWORD", []byte("s3cr3t")); err != nil {
		panic(err)
	}
	value, err := client.Get(token, "myapp/DB_PASSWORD")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(value))

	_, err = client.Get(token, "someone-elses/SECRET")
	var denied mikavt.DeniedError
	if errors.As(err, &denied) {
		fmt.Println("correctly denied")
	}
}
```

This exact flow is what
[`sdk/go/mikavt/examples/smoke/main.go`](../../sdk/go/mikavt/examples/smoke/main.go)
runs for real in CI (`scripts/sdk-smoke.sh`).

**Note:** Go's `encoding/json` encodes `[]byte` as base64 by default,
which does not match the wire protocol's plain-integer-array encoding
for `Vec<u8>` — the SDK converts explicitly on both the encode and
decode sides. If you ever bypass the SDK and speak the protocol
directly from Go, you need the same conversion.

## Server mode (TLS / mutual TLS)

```go
client, err := mikavt.ConnectTLS(mikavt.TLSOptions{
	Addr:       "mikavt.example.internal:8443",
	ServerName: "mikavt.example.internal",
	CACertPath: "/path/to/ca.pem",
	// ClientCertPath/ClientKeyPath: set both together only if the
	// server requires mutual TLS ($MIKAVT_TLS_CLIENT_CA).
})
if err != nil {
	panic(err)
}
```

Uses Go's own `crypto/tls` — no third-party TLS library. TLS 1.3 only
(`MinVersion`/`MaxVersion` both set to `tls.VersionTLS13`), the server's
certificate is verified against exactly the CA you provide (this client
never falls back to Go's system/public root store), and
`InsecureSkipVerify` is never set anywhere in this SDK. Proven for real
— including rejecting a wrong hostname, rejecting a connection with no
client cert against an mTLS-only server, and rejecting a client cert
signed by a different, untrusted CA — by
[`sdk/go/mikavt/examples/smoke_tls/main.go`](../../sdk/go/mikavt/examples/smoke_tls/main.go),
run by `scripts/server-mode-smoke.sh`.
