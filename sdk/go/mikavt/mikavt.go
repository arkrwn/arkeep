// Package mikavt is a minimal Go client SDK for mikavt. It connects to a
// running mikavtd over its Unix socket, or (server mode, ADR 0008) over
// TLS-wrapped TCP, and speaks the same newline-delimited JSON protocol
// documented in mikavtd/src/protocol.rs (Request/Response, serde's
// default externally-tagged enum encoding). It has no dependency on the
// Rust crates — just the standard library (including Go's own
// crypto/tls for the TLS transport — no third-party TLS library).
package mikavt

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

// maxLineBytes mirrors mikavtd's protocol::MAX_LINE_BYTES (and the
// Rust SDK's identical constant) — a hard ceiling on one response line,
// so a malicious or compromised daemon that never terminates a response
// can't grow this client's buffer without limit.
const maxLineBytes = 16 * 1024 * 1024

// ioTimeout bounds how long one call can block on the network — a
// stalled or malicious daemon otherwise ties up the caller's goroutine
// indefinitely. Matches mikavtd's own per-connection timeout (ADR 0008).
const ioTimeout = 30 * time.Second

type transportKind int

const (
	transportUnix transportKind = iota
	transportTLS
)

// Client talks to one mikavtd endpoint — a Unix socket, or (server
// mode) a TLS/TCP address. Each call opens a fresh connection, matching
// the convention established by mikavtd's own CLI client (simplest
// correct option, no connection-pooling complexity).
type Client struct {
	kind       transportKind
	socketPath string
	addr       string
	tlsConfig  *tls.Config
}

// Connect builds a Client for the daemon's Unix socket at socketPath.
// Does not connect yet — connection happens per call.
func Connect(socketPath string) *Client {
	return &Client{kind: transportUnix, socketPath: socketPath}
}

// TLSOptions configures a server-mode (ADR 0008) connection.
type TLSOptions struct {
	// Addr is "host:port" to connect to (matches the daemon's
	// $MIKAVT_TLS_ADDR).
	Addr string
	// ServerName is verified against the server's certificate (its
	// subject/SAN) — this is NOT where you disable verification; there
	// is no option to do that in this SDK.
	ServerName string
	// CACertPath is a PEM file containing the CA that signed the
	// server's certificate. mikavt's TLS is for a self-managed
	// deployment, not the public web — this client trusts ONLY this CA,
	// never the OS's default/system trust store.
	CACertPath string
	// ClientCertPath/ClientKeyPath (PEM), both set together, enable
	// mutual TLS — required only if the server was started with
	// $MIKAVT_TLS_CLIENT_CA.
	ClientCertPath string
	ClientKeyPath  string
}

// ConnectTLS builds a Client for the daemon's TLS/TCP listener (server
// mode, ADR 0008). Loads and validates the CA (and, if given, client
// cert/key) eagerly, so a misconfiguration fails here rather than on
// the first call.
func ConnectTLS(opts TLSOptions) (*Client, error) {
	caPEM, err := os.ReadFile(opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("reading CA cert %s: %w", opts.CACertPath, err)
	}
	// A deliberately empty, fresh pool: this client trusts ONLY the CA
	// given here. It must never fall back to x509.SystemCertPool() —
	// doing so would let any public-CA-issued certificate impersonate
	// the mikavt server.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no valid certificates found in CA file %s", opts.CACertPath)
	}

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		ServerName: opts.ServerName,
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		// InsecureSkipVerify is deliberately never set (defaults to
		// false). Hostname verification against ServerName happens
		// automatically; there is no code path in this SDK that can
		// disable it.
	}

	if opts.ClientCertPath != "" || opts.ClientKeyPath != "" {
		if opts.ClientCertPath == "" || opts.ClientKeyPath == "" {
			return nil, fmt.Errorf("both ClientCertPath and ClientKeyPath must be set together, or neither")
		}
		cert, err := tls.LoadX509KeyPair(opts.ClientCertPath, opts.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("loading client cert/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return &Client{kind: transportTLS, addr: opts.Addr, tlsConfig: tlsConfig}, nil
}

// DeniedError is returned when the token doesn't have access to the
// requested path, or the token is unknown to the daemon.
type DeniedError struct{}

func (DeniedError) Error() string { return "denied" }

// NotFoundError is returned when the requested path has no value set.
type NotFoundError struct{}

func (NotFoundError) Error() string { return "not found" }

// RemoteError wraps an error message returned by the daemon itself.
type RemoteError struct{ Message string }

func (e RemoteError) Error() string { return "remote error: " + e.Message }

// ProtocolError means the daemon's response didn't match any known
// shape, or exceeded this client's size limit.
type ProtocolError struct{ Message string }

func (e ProtocolError) Error() string { return "protocol error: " + e.Message }

func (c *Client) dial() (net.Conn, error) {
	switch c.kind {
	case transportTLS:
		conn, err := net.DialTimeout("tcp", c.addr, ioTimeout)
		if err != nil {
			return nil, fmt.Errorf("connecting to %s: %w", c.addr, err)
		}
		tlsConn := tls.Client(conn, c.tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
			tlsConn.Close()
			return nil, err
		}
		if err := tlsConn.Handshake(); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("TLS handshake with %s: %w", c.addr, err)
		}
		return tlsConn, nil
	default:
		conn, err := net.DialTimeout("unix", c.socketPath, ioTimeout)
		if err != nil {
			return nil, fmt.Errorf("connecting to %s: %w", c.socketPath, err)
		}
		return conn, nil
	}
}

// readLineBounded reads from conn until it sees '\n' or hits
// maxLineBytes, whichever comes first — never growing its buffer past
// that limit. Each Client.send call makes exactly one request and
// expects exactly one response line before the connection is closed, so
// (unlike a long-lived server loop) there is no "next request" to
// preserve in a buffered reader across calls.
func readLineBounded(conn net.Conn) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			if len(buf)+n > maxLineBytes {
				return nil, ProtocolError{Message: "response line exceeded the maximum allowed size"}
			}
			buf = append(buf, chunk[:n]...)
			if idx := indexByte(buf, '\n'); idx >= 0 {
				return buf[:idx+1], nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("reading response: %w", err)
		}
	}
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func (c *Client) send(request map[string]any) (json.RawMessage, error) {
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
		return nil, err
	}

	body, err := json.Marshal(request)
	if err != nil {
		return nil, ProtocolError{Message: "failed to encode request: " + err.Error()}
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	line, err := readLineBounded(conn)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(line), nil
}

// classify maps a raw JSON response line to either a decoded success
// value (via onValue) or one of the standard sentinel errors. Response is
// either a bare string ("Ok"/"Denied"/"NotFound") or a single-key object
// ({"Value": [...]}, {"Listed": [...]}, {"Err": "..."}).
func classify(raw json.RawMessage, onValue func(key string, payload json.RawMessage) (any, error)) (any, error) {
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		switch asString {
		case "Ok":
			return nil, nil
		case "Denied":
			return nil, DeniedError{}
		case "NotFound":
			return nil, NotFoundError{}
		default:
			return nil, ProtocolError{Message: "unknown bare response: " + asString}
		}
	}

	var asObject map[string]json.RawMessage
	if err := json.Unmarshal(raw, &asObject); err != nil {
		return nil, ProtocolError{Message: "response is neither a string nor an object: " + err.Error()}
	}
	if len(asObject) != 1 {
		return nil, ProtocolError{Message: fmt.Sprintf("expected exactly one key in response object, got %d", len(asObject))}
	}
	for key, payload := range asObject {
		if key == "Err" {
			var msg string
			if err := json.Unmarshal(payload, &msg); err != nil {
				return nil, ProtocolError{Message: "Err payload was not a string: " + err.Error()}
			}
			return nil, RemoteError{Message: msg}
		}
		return onValue(key, payload)
	}
	return nil, ProtocolError{Message: "unreachable"}
}

// Get reads a secret's value.
func (c *Client) Get(token, path string) ([]byte, error) {
	raw, err := c.send(map[string]any{"Get": map[string]string{"token": token, "path": path}})
	if err != nil {
		return nil, err
	}
	value, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
		if key != "Value" {
			return nil, ProtocolError{Message: "unexpected response key to Get: " + key}
		}
		// The wire payload is a plain JSON array of numbers (serde's
		// default Vec<u8> encoding), not a base64 string, so decode into
		// []int first rather than relying on encoding/json's []byte
		// special case (which expects base64).
		var numbers []int
		if err := json.Unmarshal(payload, &numbers); err != nil {
			return nil, ProtocolError{Message: "Value payload was not a number array: " + err.Error()}
		}
		bytes := make([]byte, len(numbers))
		for i, n := range numbers {
			bytes[i] = byte(n)
		}
		return bytes, nil
	})
	if err != nil {
		return nil, err
	}
	return value.([]byte), nil
}

// Set writes a secret's value. Requires a read-write token.
//
// Go's encoding/json encodes []byte as a base64 string by default, but
// the wire protocol (serde's default Vec<u8> encoding) expects a plain
// JSON array of numbers — so value is explicitly converted to []int
// before marshaling, matching mikavt-sdk's Rust/Python/TypeScript
// counterparts.
func (c *Client) Set(token, path string, value []byte) error {
	numbers := make([]int, len(value))
	for i, b := range value {
		numbers[i] = int(b)
	}
	raw, err := c.send(map[string]any{"Set": map[string]any{"token": token, "path": path, "value": numbers}})
	if err != nil {
		return err
	}
	_, err = classify(raw, func(key string, _ json.RawMessage) (any, error) {
		return nil, ProtocolError{Message: "unexpected response key to Set: " + key}
	})
	return err
}

// Rm removes a secret. Requires a read-write token.
func (c *Client) Rm(token, path string) error {
	raw, err := c.send(map[string]any{"Rm": map[string]string{"token": token, "path": path}})
	if err != nil {
		return err
	}
	_, err = classify(raw, func(key string, _ json.RawMessage) (any, error) {
		return nil, ProtocolError{Message: "unexpected response key to Rm: " + key}
	})
	return err
}

// List lists secret paths under prefix.
func (c *Client) List(token, prefix string) ([]string, error) {
	raw, err := c.send(map[string]any{"List": map[string]string{"token": token, "prefix": prefix}})
	if err != nil {
		return nil, err
	}
	value, err := classify(raw, func(key string, payload json.RawMessage) (any, error) {
		if key != "Listed" {
			return nil, ProtocolError{Message: "unexpected response key to List: " + key}
		}
		var paths []string
		if err := json.Unmarshal(payload, &paths); err != nil {
			return nil, ProtocolError{Message: "Listed payload was not a string array: " + err.Error()}
		}
		return paths, nil
	})
	if err != nil {
		return nil, err
	}
	return value.([]string), nil
}
