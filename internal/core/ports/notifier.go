package ports

import "golang.org/x/net/context"

// Notifier defines the interface for sending notifications
type Notifier interface {
	Notify(ctx context.Context, to any, message string) error
}
