package envunlocker

import (
	"context"
	"fmt"

	"github.com/arkade-os/arkd/internal/core/ports"
)

type service struct {
	password string
}

func NewService(password string) (ports.Unlocker, error) {
	if len(password) <= 0 {
		return nil, fmt.Errorf("missing password in env")
	}
	return &service{password}, nil
}

func (s *service) GetPassword(_ context.Context) (string, error) {
	return s.password, nil
}
