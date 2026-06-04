package mempoolexplorer

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/require"
)

func TestIsCloseError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "websocket normal closure",
			err:      &websocket.CloseError{Code: websocket.CloseNormalClosure},
			expected: true,
		},
		{
			name:     "websocket going away",
			err:      &websocket.CloseError{Code: websocket.CloseGoingAway},
			expected: true,
		},
		{
			// CloseAbnormalClosure = TCP dropped without WS close frame.
			// Must trigger reconnect, not a permanent clean close.
			name:     "websocket abnormal closure is not a close error",
			err:      &websocket.CloseError{Code: websocket.CloseAbnormalClosure},
			expected: false,
		},
		{
			name:     "net.ErrClosed",
			err:      net.ErrClosed,
			expected: true,
		},
		{
			name:     "net.ErrClosed wrapped in net.OpError",
			err:      &net.OpError{Op: "read", Err: net.ErrClosed},
			expected: true,
		},
		{
			name:     "context canceled",
			err:      context.Canceled,
			expected: true,
		},
		{
			// Exact shape produced by gorilla/websocket WriteControl on a dead TCP connection:
			// write tcp <local>-><remote>: write: broken pipe
			name: "broken pipe wrapped in net.OpError",
			err: &net.OpError{
				Op:  "write",
				Err: &os.SyscallError{Syscall: "write", Err: syscall.EPIPE},
			},
			expected: true,
		},
		{
			name:     "plain broken pipe syscall error",
			err:      fmt.Errorf("write failed: %w", syscall.EPIPE),
			expected: true,
		},
		{
			name:     "timeout error is not a close error",
			err:      os.ErrDeadlineExceeded,
			expected: false,
		},
		{
			name:     "connection reset is not a close error",
			err:      &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
			expected: false,
		},
		{
			name:     "generic error is not a close error",
			err:      fmt.Errorf("some random error"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, isCloseError(tt.err))
		})
	}
}

func TestIsTimeoutError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "os.ErrDeadlineExceeded",
			err:      os.ErrDeadlineExceeded,
			expected: true,
		},
		{
			name:     "context deadline exceeded",
			err:      context.DeadlineExceeded,
			expected: true,
		},
		{
			name: "network timeout via net.OpError",
			err: &net.OpError{
				Op:  "read",
				Err: &timeoutError{},
			},
			expected: true,
		},
		{
			name:     "ECONNRESET",
			err:      &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ECONNRESET}},
			expected: true,
		},
		{
			// CloseAbnormalClosure = TCP dropped without WS close frame → reconnect.
			name:     "websocket abnormal closure triggers reconnect",
			err:      &websocket.CloseError{Code: websocket.CloseAbnormalClosure},
			expected: true,
		},
		{
			name:     "broken pipe is not a timeout error",
			err:      &net.OpError{Op: "write", Err: &os.SyscallError{Syscall: "write", Err: syscall.EPIPE}},
			expected: false,
		},
		{
			name:     "context canceled is not a timeout error",
			err:      context.Canceled,
			expected: false,
		},
		{
			name:     "generic error is not a timeout error",
			err:      fmt.Errorf("something went wrong"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.expected, isTimeoutError(tt.err))
		})
	}
}

// timeoutError is a helper that implements the Timeout() bool interface.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }
