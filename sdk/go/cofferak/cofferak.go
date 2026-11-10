// Package cofferak is a minimal Go client SDK for cofferak. It connects to a
// running cofferakd over its Unix socket and speaks the same
// newline-delimited JSON protocol documented in cofferakd/src/protocol.rs
// (Request/Response, serde's default externally-tagged enum encoding).
// It has no dependency on the Rust crates — just the standard library.
package cofferak

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
)

// Client talks to one cofferakd Unix socket. Each call opens a fresh
// connection, matching the convention established by cofferakd's own CLI
// client (simplest correct option, no connection-pooling complexity).
type Client struct {
	SocketPath string
}

// Connect builds a Client for the daemon's socket at socketPath. It does
// not connect yet — connection happens per call.
func Connect(socketPath string) *Client {
	return &Client{SocketPath: socketPath}
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

// ProtocolError means the daemon's response didn't match any known shape.
type ProtocolError struct{ Message string }

func (e ProtocolError) Error() string { return "protocol error: " + e.Message }

func (c *Client) send(request map[string]any) (json.RawMessage, error) {
	conn, err := net.Dial("unix", c.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	body, err := json.Marshal(request)
	if err != nil {
		return nil, ProtocolError{Message: "failed to encode request: " + err.Error()}
	}
	if _, err := conn.Write(append(body, '\n')); err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
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
// before marshaling, matching cofferak-sdk's Rust/Python/TypeScript
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
