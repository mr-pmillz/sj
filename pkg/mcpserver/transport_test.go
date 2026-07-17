package mcpserver

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBoundedMessageReaderEnforcesEachProtocolMessage(t *testing.T) {
	reader := newBoundedMessageReader(io.NopCloser(strings.NewReader("1234\n12\n")), 5)
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "1234\n12\n" {
		t.Fatalf("data = %q", data)
	}
}

func TestBoundedMessageReaderRejectsBeforeExposingOversizedMessage(t *testing.T) {
	reader := newBoundedMessageReader(io.NopCloser(strings.NewReader("123456\n")), 5)
	buffer := make([]byte, 16)
	n, err := reader.Read(buffer)
	if n != 0 || !errors.Is(err, errMCPMessageTooLarge) {
		t.Fatalf("Read = %d, %v; want 0, errMCPMessageTooLarge", n, err)
	}
}

func TestNewStdioTransportRejectsInvalidBounds(t *testing.T) {
	for _, limit := range []int64{-1, 0, maximumMCPMessageBytes + 1} {
		if _, err := NewStdioTransport(limit); err == nil {
			t.Fatalf("NewStdioTransport accepted limit %d", limit)
		}
	}
}
