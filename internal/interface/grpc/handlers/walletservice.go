package handlers

import (
	"context"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/ports"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type walletInitHandler struct {
	walletService ports.WalletService
	onUnlock      func(password string) error
	onReady       func()
}

func NewWalletInitializerHandler(
	walletService ports.WalletService, onUnlock func(string) error, onReady func(),
) arkv1.WalletInitializerServiceServer {
	svc := walletInitHandler{walletService, onUnlock, onReady}
	if onReady != nil {
		go svc.listenWhenReady()
	}
	return &svc
}

// errWalletManagedExternally is returned by the wallet lifecycle RPCs that arkd
// no longer handles: each arkd-wallet must be initialized out of band.
const errWalletManagedExternally = "arkd no longer manages the wallet: " +
	"initialize the arkd-wallet directly"

// errWalletLockManagedExternally is returned by the Lock RPC: arkd no longer
// locks the (possibly shared) wallet; lock it out of band instead.
const errWalletLockManagedExternally = "arkd no longer manages the wallet: " +
	"lock the arkd-wallet directly"

func (a *walletInitHandler) GenSeed(
	_ context.Context, _ *arkv1.GenSeedRequest,
) (*arkv1.GenSeedResponse, error) {
	return nil, status.Error(codes.Unimplemented, errWalletManagedExternally)
}

func (a *walletInitHandler) Create(
	_ context.Context, _ *arkv1.CreateRequest,
) (*arkv1.CreateResponse, error) {
	return nil, status.Error(codes.Unimplemented, errWalletManagedExternally)
}

func (a *walletInitHandler) Restore(
	_ context.Context, _ *arkv1.RestoreRequest,
) (*arkv1.RestoreResponse, error) {
	return nil, status.Error(codes.Unimplemented, errWalletManagedExternally)
}

// Unlock no longer unlocks the wallet (which must already be unlocked out of
// band); it only unlocks the macaroon (admin auth) service with the given
// password.
func (a *walletInitHandler) Unlock(
	_ context.Context, req *arkv1.UnlockRequest,
) (*arkv1.UnlockResponse, error) {
	if len(req.GetPassword()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing password")
	}

	if a.onUnlock != nil {
		if err := a.onUnlock(req.GetPassword()); err != nil {
			return nil, status.Error(codes.Internal, err.Error())
		}
	}

	return &arkv1.UnlockResponse{}, nil
}

func (a *walletInitHandler) GetStatus(
	ctx context.Context, _ *arkv1.GetStatusRequest,
) (*arkv1.GetStatusResponse, error) {
	walletStatus, err := a.walletService.Status(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetStatusResponse{
		Initialized: walletStatus.IsInitialized(),
		Unlocked:    walletStatus.IsUnlocked(),
		Synced:      walletStatus.IsSynced(),
	}, nil
}

func (a *walletInitHandler) listenWhenReady() {
	ctx := context.Background()
	ch, err := a.walletService.GetReadyUpdate(ctx)
	if err != nil {
		log.WithError(err).Warn("failed to get wallet ready update")
		return
	}

	for ready := range ch {
		if ready && a.onReady != nil {
			a.onReady()
		}
	}
}

type walletHandler struct {
	walletService ports.WalletService
}

func NewWalletHandler(walletService ports.WalletService) arkv1.WalletServiceServer {
	return &walletHandler{walletService}
}

func (a *walletHandler) Lock(
	_ context.Context, _ *arkv1.LockRequest,
) (*arkv1.LockResponse, error) {
	// arkd no longer manages the wallet lifecycle; locking the (possibly shared)
	// wallet via arkd would break every other consumer, so the RPC is disabled
	// — lock the wallet out of band through arkd-wallet directly.
	return nil, status.Error(codes.Unimplemented, errWalletLockManagedExternally)
}

func (a *walletHandler) DeriveAddress(
	ctx context.Context, _ *arkv1.DeriveAddressRequest,
) (*arkv1.DeriveAddressResponse, error) {
	addr, err := a.walletService.DeriveAddresses(ctx, 1)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.DeriveAddressResponse{Address: addr[0]}, nil
}

func (a *walletHandler) GetBalance(
	ctx context.Context, _ *arkv1.GetBalanceRequest,
) (*arkv1.GetBalanceResponse, error) {
	availableMainBalance, lockedMainBalance, err := a.walletService.MainAccountBalance(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	availableConnBalance, lockedConnBalance, err := a.walletService.ConnectorsAccountBalance(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GetBalanceResponse{
		MainAccount: &arkv1.Balance{
			Locked:    convertSatsToBTCStr(lockedMainBalance),
			Available: convertSatsToBTCStr(availableMainBalance),
		},
		ConnectorsAccount: &arkv1.Balance{
			Locked:    convertSatsToBTCStr(lockedConnBalance),
			Available: convertSatsToBTCStr(availableConnBalance),
		},
	}, nil
}

func (a *walletHandler) Withdraw(
	ctx context.Context, req *arkv1.WithdrawRequest,
) (*arkv1.WithdrawResponse, error) {
	if req.GetAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	if !req.GetAll() && req.GetAmount() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be greater than 0")
	}

	txid, err := a.walletService.Withdraw(ctx, req.GetAddress(), req.GetAmount(), req.GetAll())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &arkv1.WithdrawResponse{Txid: txid}, nil
}
