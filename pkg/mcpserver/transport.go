package mcpserver

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const maximumMCPMessageBytes int64 = 1 << 30

var errMCPMessageTooLarge = errors.New("MCP message exceeds configured size limit")

// NewStdioTransport returns the SDK's newline-delimited IO transport with a
// hard per-message input limit. The SDK otherwise decodes stdin before a tool
// handler can apply its own document bounds.
func NewStdioTransport(maxMessageBytes int64) (mcp.Transport, error) {
	if maxMessageBytes < 1 || maxMessageBytes > maximumMCPMessageBytes {
		return nil, fmt.Errorf("MCP input message limit must be between 1 and %d bytes", maximumMCPMessageBytes)
	}
	return &mcp.IOTransport{
		Reader: newBoundedMessageReader(os.Stdin, maxMessageBytes),
		Writer: nopWriteCloser{Writer: os.Stdout},
	}, nil
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error { return nil }

type boundedMessageReader struct {
	reader     *bufio.Reader
	closer     io.Closer
	maxBytes   int64
	buffer     []byte
	pendingErr error
}

func newBoundedMessageReader(reader io.ReadCloser, maxBytes int64) *boundedMessageReader {
	return &boundedMessageReader{reader: bufio.NewReader(reader), closer: reader, maxBytes: maxBytes}
}

func (reader *boundedMessageReader) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if len(reader.buffer) == 0 {
		if reader.pendingErr != nil {
			err := reader.pendingErr
			reader.pendingErr = nil
			return 0, err
		}
		if err := reader.readMessage(); err != nil {
			return 0, err
		}
	}
	n := copy(destination, reader.buffer)
	reader.buffer = reader.buffer[n:]
	return n, nil
}

func (reader *boundedMessageReader) readMessage() error {
	message := make([]byte, 0, min(reader.maxBytes, 64*1024))
	for {
		fragment, err := reader.reader.ReadSlice('\n')
		if int64(len(message))+int64(len(fragment)) > reader.maxBytes {
			return errMCPMessageTooLarge
		}
		message = append(message, fragment...)
		switch {
		case err == nil:
			reader.buffer = message
			return nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(message) > 0:
			reader.buffer = message
			reader.pendingErr = io.EOF
			return nil
		default:
			return err
		}
	}
}

func (reader *boundedMessageReader) Close() error {
	return reader.closer.Close()
}
