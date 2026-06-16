package ports

import "github.com/arkade-os/arkd/internal/core/domain"

type RepoManager interface {
	Events() domain.EventRepository
	Rounds() domain.RoundRepository
	Vtxos() domain.VtxoRepository
	OffchainTxs() domain.OffchainTxRepository
	Convictions() domain.ConvictionRepository
	Assets() domain.AssetRepository
	Settings() domain.SettingsRepository
	RegisterBatchUpdateHandler(handler func(data domain.Round))
	RegisterOffchainTxUpdateHandler(handler func(data domain.OffchainTx))
	RegisterSettingsUpdateHandler(handler func(data domain.Settings, changelog []string))
	Close()
}
