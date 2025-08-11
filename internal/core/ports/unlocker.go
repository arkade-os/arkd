package ports

import "context"

type Unlocker interface {
	GetPassword(ctx context.Context) (string, error)
}
