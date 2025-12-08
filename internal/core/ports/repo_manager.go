package ports

import "github.com/arkade-os/arkd/internal/core/domain"

type RepoManager interface {
	Events() domain.EventRepository
	Rounds() domain.RoundRepository
	Vtxos() domain.VtxoRepository
	ScheduledSession() domain.ScheduledSessionRepo
	OffchainTxs() domain.OffchainTxRepository
	Convictions() domain.ConvictionRepository
	Assets() domain.AssetRepository
	Close()
}
