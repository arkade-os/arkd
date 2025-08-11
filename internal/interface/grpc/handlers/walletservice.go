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
	onInit        func(password string)
	onUnlock      func(password string)
	onReady       func()
}

func NewWalletInitializerHandler(
	walletService ports.WalletService, onInit, onUnlock func(string), onReady func(),
) arkv1.WalletInitializerServiceServer {
	svc := walletInitHandler{walletService, onInit, onUnlock, onReady}
	if onInit != nil && onUnlock != nil && onReady != nil {
		go svc.listenWhenReady()
	}
	return &svc
}

func (a *walletInitHandler) GenSeed(
	ctx context.Context, _ *arkv1.GenSeedRequest,
) (*arkv1.GenSeedResponse, error) {
	seed, err := a.walletService.GenSeed(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.GenSeedResponse{Seed: seed}, nil
}

func (a *walletInitHandler) Create(
	ctx context.Context, req *arkv1.CreateRequest,
) (*arkv1.CreateResponse, error) {
	if len(req.GetSeed()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing wallet seed")
	}
	if len(req.GetPassword()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing wallet password")
	}

	if err := a.walletService.Create(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	go a.onInit(req.GetPassword())

	return &arkv1.CreateResponse{}, nil
}

func (a *walletInitHandler) Restore(
	ctx context.Context, req *arkv1.RestoreRequest,
) (*arkv1.RestoreResponse, error) {
	if len(req.GetSeed()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing wallet seed")
	}
	if len(req.GetPassword()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing wallet password")
	}

	if err := a.walletService.Restore(ctx, req.GetSeed(), req.GetPassword()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	go a.onInit(req.GetPassword())

	return &arkv1.RestoreResponse{}, nil
}

func (a *walletInitHandler) Unlock(
	ctx context.Context, req *arkv1.UnlockRequest,
) (*arkv1.UnlockResponse, error) {
	if len(req.GetPassword()) <= 0 {
		return nil, status.Error(codes.InvalidArgument, "missing wallet password")
	}
	if err := a.walletService.Unlock(ctx, req.GetPassword()); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	go a.onUnlock(req.GetPassword())

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

	_, ok := <-ch
	if !ok {
		return
	}

	a.onReady()
}

type walletHandler struct {
	walletService ports.WalletService
}

func NewWalletHandler(walletService ports.WalletService) arkv1.WalletServiceServer {
	return &walletHandler{walletService}
}

func (a *walletHandler) Lock(
	ctx context.Context, _ *arkv1.LockRequest,
) (*arkv1.LockResponse, error) {
	if err := a.walletService.Lock(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.LockResponse{}, nil
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
	if req.GetAmount() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be greater than 0")
	}

	if req.GetAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	txid, err := a.walletService.Withdraw(ctx, req.GetAddress(), req.GetAmount())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &arkv1.WithdrawResponse{Txid: txid}, nil
}
