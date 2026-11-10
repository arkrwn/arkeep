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
