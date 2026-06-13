package handlers

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/interface/grpc/interceptors"
	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/macaroons"
	"github.com/go-macaroon-bakery/macaroonpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon.v2"
)

type tokenAdminInterface interface {
	ListTokens(
		ctx context.Context,
		token, hash, outpoint, txid string,
	) ([]application.TokenEntry, error)
	RevokeTokens(ctx context.Context, token, hash, outpoint, txid string) (int, error)
}

type adminHandler struct {
	adminService    application.AdminService
	tokenAdminSvc   tokenAdminInterface
	macaroonSvc     *macaroons.Service
	macaroonDatadir string
	noteUriPrefix   string
}

func NewAdminHandler(
	adminService application.AdminService,
	indexerService application.IndexerService,
	macaroonSvc *macaroons.Service,
	macaroonDatadir, noteUriPrefix string,
) arkv1.AdminServiceServer {
	return &adminHandler{
		adminService:    adminService,
		tokenAdminSvc:   indexerService,
		macaroonSvc:     macaroonSvc,
		macaroonDatadir: macaroonDatadir,
		noteUriPrefix:   noteUriPrefix,
	}
}

func (a *adminHandler) GetRoundDetails(
	ctx context.Context, req *arkv1.GetRoundDetailsRequest,
) (*arkv1.GetRoundDetailsResponse, error) {
	id := req.GetRoundId()
	if len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	details, err := a.adminService.GetRoundDetails(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetRoundDetailsResponse{
		RoundId:          details.RoundId,
		CommitmentTxid:   details.TxId,
		ForfeitedAmount:  convertSatsToBTCStr(details.ForfeitedAmount),
		TotalVtxosAmount: convertSatsToBTCStr(details.TotalVtxosAmount),
		TotalExitAmount:  convertSatsToBTCStr(details.TotalExitAmount),
		TotalFeeAmount:   convertSatsToBTCStr(details.FeesAmount),
		InputsVtxos:      details.InputVtxos,
		OutputsVtxos:     details.OutputVtxos,
		ExitAddresses:    details.ExitAddresses,
		StartedAt:        details.StartedAt,
		EndedAt:          details.EndedAt,
	}, nil
}

func (a *adminHandler) GetRounds(
	ctx context.Context, req *arkv1.GetRoundsRequest,
) (*arkv1.GetRoundsResponse, error) {
	startAfter := req.GetAfter()
	startBefore := req.GetBefore()
	withFailed := req.GetWithFailed()
	withCompleted := req.GetWithCompleted()

	if startAfter < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid after (must be >= 0)")
	}

	if startBefore < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid before (must be >= 0)")
	}

	if startAfter >= startBefore {
		return nil, status.Error(codes.InvalidArgument, "invalid range")
	}

	rounds, err := a.adminService.GetRounds(ctx, startAfter, startBefore, withFailed, withCompleted)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetRoundsResponse{Rounds: rounds}, nil
}

func (a *adminHandler) GetExpiringLiquidity(
	ctx context.Context, req *arkv1.GetExpiringLiquidityRequest,
) (*arkv1.GetExpiringLiquidityResponse, error) {
	after := req.GetAfter()
	before := req.GetBefore()

	// Treat 0 or negative values as "unset" (proto doesn't support nil for scalars here).
	// - after <= 0 -> now
	// - before <= 0 -> no upper bound
	if after <= 0 {
		after = time.Now().Unix()
	}

	if before > 0 && after >= before {
		return nil, status.Error(codes.InvalidArgument, "invalid range")
	}

	amount, err := a.adminService.GetExpiringLiquidity(ctx, after, before)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetExpiringLiquidityResponse{Amount: amount}, nil
}

func (a *adminHandler) GetRecoverableLiquidity(
	ctx context.Context, _ *arkv1.GetRecoverableLiquidityRequest,
) (*arkv1.GetRecoverableLiquidityResponse, error) {
	amount, err := a.adminService.GetRecoverableLiquidity(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetRecoverableLiquidityResponse{Amount: amount}, nil
}

func (a *adminHandler) GetScheduledSweep(
	ctx context.Context, _ *arkv1.GetScheduledSweepRequest,
) (*arkv1.GetScheduledSweepResponse, error) {
	scheduledSweeps, err := a.adminService.GetScheduledSweeps(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	sweeps := make([]*arkv1.ScheduledSweep, 0)
	for _, sweep := range scheduledSweeps {
		outputs := make([]*arkv1.SweepableOutput, 0)

		for _, output := range sweep.SweepableOutputs {
			outputs = append(outputs, &arkv1.SweepableOutput{
				Txid:        output.TxInput.Txid,
				Vout:        output.TxInput.Index,
				ScheduledAt: output.ScheduledAt,
				Amount:      convertSatsToBTCStr(output.TxInput.Value),
			})
		}

		sweeps = append(sweeps, &arkv1.ScheduledSweep{
			RoundId:   sweep.RoundId,
			Confirmed: sweep.Confirmed,
			Outputs:   outputs,
		})
	}

	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}, nil
}

func (a *adminHandler) GetExpiredRounds(
	ctx context.Context, _ *arkv1.GetExpiredRoundsRequest,
) (*arkv1.GetExpiredRoundsResponse, error) {
	expiredRounds, err := a.adminService.GetExpiredRounds(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	rounds := make([]*arkv1.ExpiredRound, 0, len(expiredRounds))
	for _, round := range expiredRounds {
		rounds = append(rounds, &arkv1.ExpiredRound{
			RoundId:        round.RoundId,
			CommitmentTxid: round.CommitmentTxid,
			ExpiredAt:      round.ExpiredAt,
		})
	}

	return &arkv1.GetExpiredRoundsResponse{Rounds: rounds}, nil
}

func (a *adminHandler) CreateNote(
	ctx context.Context, req *arkv1.CreateNoteRequest,
) (*arkv1.CreateNoteResponse, error) {
	amount := req.GetAmount()
	quantity := req.GetQuantity()
	if quantity == 0 {
		quantity = 1
	}

	if amount == 0 {
		return nil, status.Error(codes.InvalidArgument, "amount must be greater than 0")
	}

	notes, err := a.adminService.CreateNotes(ctx, amount, int(quantity))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	if len(a.noteUriPrefix) <= 0 {
		return &arkv1.CreateNoteResponse{Notes: notes}, nil
	}

	notesWithURI := make([]string, 0, len(notes))
	for _, note := range notes {
		notesWithURI = append(notesWithURI, fmt.Sprintf("%s://%s", a.noteUriPrefix, note))
	}
	return &arkv1.CreateNoteResponse{Notes: notesWithURI}, nil
}

func (a *adminHandler) GetScheduledSessionConfig(
	ctx context.Context, _ *arkv1.GetScheduledSessionConfigRequest,
) (*arkv1.GetScheduledSessionConfigResponse, error) {
	scheduledSession, err := a.adminService.GetScheduledSession(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	var config *arkv1.ScheduledSessionConfig
	if scheduledSession != nil {
		config = &arkv1.ScheduledSessionConfig{
			StartTime:                 *formatTime(scheduledSession.StartTime),
			EndTime:                   *formatTime(scheduledSession.EndTime),
			Period:                    int64(scheduledSession.Period.Minutes()),
			Duration:                  int64(scheduledSession.Duration.Seconds()),
			RoundMinParticipantsCount: scheduledSession.RoundMinParticipantsCount,
			RoundMaxParticipantsCount: scheduledSession.RoundMaxParticipantsCount,
		}
	}

	return &arkv1.GetScheduledSessionConfigResponse{Config: config}, nil
}

func (a *adminHandler) UpdateScheduledSessionConfig(
	ctx context.Context, req *arkv1.UpdateScheduledSessionConfigRequest,
) (*arkv1.UpdateScheduledSessionConfigResponse, error) {
	cfg := req.GetConfig()
	if cfg == nil {
		return nil, status.Error(codes.InvalidArgument, "missing scheduled session config")
	}
	startTime, err := parseTime(cfg.GetStartTime())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid start time: %s", err)
	}
	endTime, err := parseTime(cfg.GetEndTime())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid end time: %s", err)
	}
	period := time.Duration(cfg.GetPeriod()) * time.Minute
	duration := time.Duration(cfg.GetDuration()) * time.Second
	roundMinParticipantsCount := cfg.GetRoundMinParticipantsCount()
	roundMaxParticipantsCount := cfg.GetRoundMaxParticipantsCount()
	if roundMinParticipantsCount != 0 && roundMaxParticipantsCount != 0 &&
		roundMinParticipantsCount > roundMaxParticipantsCount {
		return nil, status.Error(
			codes.InvalidArgument,
			"round min participants count must be less than or equal to max participants count",
		)
	}

	updates := domain.ScheduledSessionUpdate{
		StartTime:                 startTime,
		EndTime:                   endTime,
		Period:                    &period,
		Duration:                  &duration,
		RoundMinParticipantsCount: &roundMinParticipantsCount,
		RoundMaxParticipantsCount: &roundMaxParticipantsCount,
	}
	if err := a.adminService.UpdateScheduledSession(ctx, updates); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UpdateScheduledSessionConfigResponse{}, nil
}

func (a *adminHandler) ClearScheduledSessionConfig(
	ctx context.Context, req *arkv1.ClearScheduledSessionConfigRequest,
) (*arkv1.ClearScheduledSessionConfigResponse, error) {
	if err := a.adminService.ClearScheduledSession(ctx); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.ClearScheduledSessionConfigResponse{}, nil
}

func (a *adminHandler) ListIntents(
	ctx context.Context, req *arkv1.ListIntentsRequest,
) (*arkv1.ListIntentsResponse, error) {
	intents, err := a.adminService.ListIntents(ctx, req.GetIntentIds()...)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.ListIntentsResponse{Intents: intentsInfo(intents).toProto()}, nil
}

func (a *adminHandler) DeleteIntents(
	ctx context.Context, req *arkv1.DeleteIntentsRequest,
) (*arkv1.DeleteIntentsResponse, error) {
	if err := a.adminService.DeleteIntents(ctx, req.GetIntentIds()...); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.DeleteIntentsResponse{}, nil
}

func (a *adminHandler) GetConvictions(
	ctx context.Context, req *arkv1.GetConvictionsRequest,
) (*arkv1.GetConvictionsResponse, error) {
	ids := req.GetIds()
	if len(ids) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing conviction id")
	}

	convictions, err := a.adminService.GetConvictionsByIds(ctx, ids)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoConvictions := make([]*arkv1.Conviction, 0, len(convictions))
	for _, conviction := range convictions {
		protoConviction, err := convertConvictionToProto(conviction)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to convert conviction: %s",
				err.Error(),
			)
		}
		protoConvictions = append(protoConvictions, protoConviction)
	}

	return &arkv1.GetConvictionsResponse{Convictions: protoConvictions}, nil
}

func (a *adminHandler) GetConvictionsInRange(
	ctx context.Context, req *arkv1.GetConvictionsInRangeRequest,
) (*arkv1.GetConvictionsInRangeResponse, error) {
	from := time.Unix(req.GetFrom(), 0)
	to := time.Unix(req.GetTo(), 0)

	if req.GetFrom() < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid from timestamp (must be >= 0)")
	}

	if req.GetTo() < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid to timestamp (must be >= 0)")
	}

	if req.GetFrom() >= req.GetTo() {
		return nil, status.Error(codes.InvalidArgument, "invalid time range")
	}

	convictions, err := a.adminService.GetConvictions(ctx, from, to)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoConvictions := make([]*arkv1.Conviction, len(convictions))
	for i, conviction := range convictions {
		protoConviction, err := convertConvictionToProto(conviction)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to convert conviction: %s",
				err.Error(),
			)
		}
		protoConvictions[i] = protoConviction
	}

	return &arkv1.GetConvictionsInRangeResponse{Convictions: protoConvictions}, nil
}

func (a *adminHandler) GetConvictionsByRound(
	ctx context.Context, req *arkv1.GetConvictionsByRoundRequest,
) (*arkv1.GetConvictionsByRoundResponse, error) {
	roundID := req.GetRoundId()
	if len(roundID) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing round id")
	}

	convictions, err := a.adminService.GetConvictionsByRound(ctx, roundID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoConvictions := make([]*arkv1.Conviction, len(convictions))
	for i, conviction := range convictions {
		protoConviction, err := convertConvictionToProto(conviction)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to convert conviction: %s",
				err.Error(),
			)
		}
		protoConvictions[i] = protoConviction
	}

	return &arkv1.GetConvictionsByRoundResponse{Convictions: protoConvictions}, nil
}

func (a *adminHandler) GetActiveScriptConvictions(
	ctx context.Context, req *arkv1.GetActiveScriptConvictionsRequest,
) (*arkv1.GetActiveScriptConvictionsResponse, error) {
	script := req.GetScript()
	if len(script) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing script")
	}

	conviction, err := a.adminService.GetActiveScriptConvictions(ctx, script)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoConvictions := make([]*arkv1.Conviction, 0, len(conviction))
	for _, conviction := range conviction {
		protoConviction, err := convertConvictionToProto(conviction)
		if err != nil {
			return nil, status.Errorf(
				codes.Internal,
				"failed to convert conviction: %s",
				err.Error(),
			)
		}
		protoConvictions = append(protoConvictions, protoConviction)
	}

	return &arkv1.GetActiveScriptConvictionsResponse{Convictions: protoConvictions}, nil
}

func (a *adminHandler) PardonConviction(
	ctx context.Context, req *arkv1.PardonConvictionRequest,
) (*arkv1.PardonConvictionResponse, error) {
	id := req.GetId()
	if len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing conviction id")
	}

	if err := a.adminService.PardonConviction(ctx, id); err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.PardonConvictionResponse{}, nil
}

func (a *adminHandler) BanScript(
	ctx context.Context, req *arkv1.BanScriptRequest,
) (*arkv1.BanScriptResponse, error) {
	script := req.GetScript()
	if len(script) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing script")
	}

	banDuration := req.GetBanDuration()
	var banTime *time.Duration

	if banDuration > 0 {
		duration := time.Duration(banDuration) * time.Second
		banTime = &duration
	}

	if err := a.adminService.BanScript(ctx, script, req.GetReason(), banTime); err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.BanScriptResponse{}, nil
}

func (a *adminHandler) GetCollectedFees(
	ctx context.Context, req *arkv1.GetCollectedFeesRequest,
) (*arkv1.GetCollectedFeesResponse, error) {
	after := req.GetAfter()
	before := req.GetBefore()

	if after < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid after (must be >= 0)")
	}
	if before < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid before (must be >= 0)")
	}
	if before > 0 && after >= before {
		return nil, status.Error(codes.InvalidArgument, "invalid range")
	}

	fees, err := a.adminService.GetCollectedFees(ctx, after, before)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetCollectedFeesResponse{CollectedFees: fees}, nil
}

func (a *adminHandler) Sweep(
	ctx context.Context, req *arkv1.SweepRequest,
) (*arkv1.SweepResponse, error) {
	withConnectors := req.GetConnectors()
	commitmentTxids := req.GetCommitmentTxids()

	txid, hex, err := a.adminService.Sweep(ctx, withConnectors, commitmentTxids)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.SweepResponse{
		Txid: txid,
		Hex:  hex,
	}, nil
}

func (a *adminHandler) GetMainAccountUtxos(
	ctx context.Context, _ *arkv1.GetMainAccountUtxosRequest,
) (*arkv1.GetMainAccountUtxosResponse, error) {
	utxos, err := a.adminService.GetMainAccountUtxos(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	resp := make([]*arkv1.WalletUtxo, 0, len(utxos))
	for _, u := range utxos {
		resp = append(resp, &arkv1.WalletUtxo{
			Txid:          u.Txid,
			Vout:          u.Vout,
			Value:         u.Value,
			Script:        u.Script,
			Address:       u.Address,
			Confirmations: u.Confirmations,
			Locked:        u.Locked,
		})
	}

	return &arkv1.GetMainAccountUtxosResponse{Utxos: resp}, nil
}

func (a *adminHandler) RevokeAuth(
	ctx context.Context, req *arkv1.RevokeAuthRequest,
) (*arkv1.RevokeAuthResponse, error) {
	if a.macaroonSvc == nil {
		return &arkv1.RevokeAuthResponse{}, nil
	}

	mac, id, ops, err := parseMacaroon(req.GetToken())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Make sure the given macaroon is valid.
	testCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("macaroon", mac))
	if err := interceptors.CheckMacaroon(
		testCtx, "/ark.v1.WalletService/GetBalance", a.macaroonSvc,
	); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	// Superuser macaroon can't be revoked.
	if bytes.Contains(id, []byte("superuser")) {
		return nil, status.Error(codes.InvalidArgument, "invalid token")
	}

	// Create the new macaroon and delete the old one (handled by BakeMacaroon).
	role := strings.Split(string(id), "-")[0]
	macBytes, err := a.macaroonSvc.BakeMacaroon(ctx, ops, role)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	macFile := filepath.Join(a.macaroonDatadir, fmt.Sprintf("%s.macaroon", role))
	perms := fs.FileMode(0644)
	if role == "admin" {
		perms = fs.FileMode(0600)
	}
	if err := os.WriteFile(macFile, macBytes, perms); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.RevokeAuthResponse{
		Token: hex.EncodeToString(macBytes),
	}, nil
}

// TODO: move ListTokens and RevokeTokens to the indexer's own admin interface when we detach it.
func (a *adminHandler) ListTokens(
	ctx context.Context, req *arkv1.ListTokensRequest,
) (*arkv1.ListTokensResponse, error) {
	tokens, err := a.tokenAdminSvc.ListTokens(
		ctx, req.GetToken(), req.GetHash(), req.GetOutpoint(), req.GetTxid(),
	)
	if err != nil {
		if errors.Is(err, application.ErrInvalidInput) {
			return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoTokens := make([]*arkv1.TokenInfo, 0, len(tokens))
	for _, t := range tokens {
		protoTokens = append(protoTokens, &arkv1.TokenInfo{
			Hash:      t.Hash,
			Outpoints: t.Outpoints,
			ExpiresAt: t.ExpiresAt.Unix(),
		})
	}

	return &arkv1.ListTokensResponse{Tokens: protoTokens}, nil
}

func (a *adminHandler) RevokeTokens(
	ctx context.Context, req *arkv1.RevokeTokensRequest,
) (*arkv1.RevokeTokensResponse, error) {
	if req.GetToken() == "" && req.GetHash() == "" && req.GetOutpoint() == "" &&
		req.GetTxid() == "" {
		return nil, status.Error(codes.InvalidArgument, "at least one filter is required")
	}

	count, err := a.tokenAdminSvc.RevokeTokens(
		ctx, req.GetToken(), req.GetHash(), req.GetOutpoint(), req.GetTxid(),
	)
	if err != nil {
		if errors.Is(err, application.ErrInvalidInput) {
			return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
		}
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.RevokeTokensResponse{RevokedCount: int32(count)}, nil
}

func (a *adminHandler) GetIntentFees(
	ctx context.Context, req *arkv1.GetIntentFeesRequest,
) (*arkv1.GetIntentFeesResponse, error) {
	fees, err := a.adminService.GetBatchFees(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetIntentFeesResponse{
		Fees: &arkv1.IntentFees{
			OffchainInputFee:  fees.OffchainInputFee,
			OnchainInputFee:   fees.OnchainInputFee,
			OffchainOutputFee: fees.OffchainOutputFee,
			OnchainOutputFee:  fees.OnchainOutputFee,
		},
	}, nil
}

func (a *adminHandler) UpdateIntentFees(
	ctx context.Context, req *arkv1.UpdateIntentFeesRequest,
) (*arkv1.UpdateIntentFeesResponse, error) {
	updates, err := parseFees(req.GetFees())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if err := a.adminService.UpdateBatchFees(ctx, *updates); err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.UpdateIntentFeesResponse{}, nil
}

func (a *adminHandler) ClearIntentFees(
	ctx context.Context, req *arkv1.ClearIntentFeesRequest,
) (*arkv1.ClearIntentFeesResponse, error) {
	if err := a.adminService.ClearBatchFees(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.ClearIntentFeesResponse{}, nil
}

func (a *adminHandler) GetSettings(
	ctx context.Context, _ *arkv1.GetSettingsRequest,
) (*arkv1.GetSettingsResponse, error) {
	settings, err := a.adminService.GetSettings(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	var protoSettings *arkv1.Settings
	if settings != nil {
		protoSettings = &arkv1.Settings{
			SessionDuration:               formatDuration(settings.SessionDuration),
			UnrolledVtxoMinExpiryMargin:   formatDuration(settings.UnrolledVtxoMinExpiryMargin),
			BanThreshold:                  formatUint64(settings.BanThreshold),
			BanDuration:                   formatDuration(settings.BanDuration),
			UnilateralExitDelay:           formatLocktime(settings.UnilateralExitDelay),
			PublicUnilateralExitDelay:     formatLocktime(settings.PublicUnilateralExitDelay),
			CheckpointExitDelay:           formatLocktime(settings.CheckpointExitDelay),
			BoardingExitDelay:             formatLocktime(settings.BoardingExitDelay),
			VtxoTreeExpiry:                formatLocktime(settings.VtxoTreeExpiry),
			RoundMinParticipantsCount:     &settings.RoundMinParticipantsCount,
			RoundMaxParticipantsCount:     &settings.RoundMaxParticipantsCount,
			VtxoMinAmount:                 &settings.VtxoMinAmount,
			VtxoMaxAmount:                 &settings.VtxoMaxAmount,
			UtxoMinAmount:                 &settings.UtxoMinAmount,
			UtxoMaxAmount:                 &settings.UtxoMaxAmount,
			SettlementMinExpiryGap:        formatDuration(settings.SettlementMinExpiryGap),
			VtxoNoCsvValidationCutoffDate: formatTime(settings.VtxoNoCsvValidationCutoffDate),
			MaxTxWeight:                   formatUint64(settings.MaxTxWeight),
			MaxOpReturnOutputs:            formatUint64(settings.MaxOpReturnOutputs),
			AssetTxMaxWeightRatio:         &settings.AssetTxMaxWeightRatio,
			NoteUriPrefix:                 &settings.NoteUriPrefix,
			BuildVersionHeader:            &settings.BuildVersionHeader,
			BuildVersionHeaderRequired:    &settings.BuildVersionHeaderRequired,
			DigestHeaderRequired:          &settings.DigestHeaderRequired,
			WalletAddr:                    &settings.WalletAddr,
			WalletFallbackAddrs:           settings.WalletFallbackAddrs,
			UpdatedAt:                     formatTime(settings.UpdatedAt),
		}
	}

	return &arkv1.GetSettingsResponse{Settings: protoSettings}, nil
}

func (a *adminHandler) UpdateSettings(
	ctx context.Context, req *arkv1.UpdateSettingsRequest,
) (*arkv1.UpdateSettingsResponse, error) {
	updates, err := parseSettings(req.GetSettings())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	changelog, err := a.adminService.UpdateSettings(ctx, *updates)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UpdateSettingsResponse{ChangeLog: changelog}, nil
}

func convertConvictionToProto(conviction domain.Conviction) (*arkv1.Conviction, error) {
	var expiresAt int64
	if conviction.GetExpiresAt() != nil {
		expiresAt = conviction.GetExpiresAt().Unix()
	}

	convictionType := arkv1.ConvictionType_CONVICTION_TYPE_UNSPECIFIED
	if conviction.GetType() == domain.ConvictionTypeScript {
		convictionType = arkv1.ConvictionType_CONVICTION_TYPE_SCRIPT
	}

	protoConviction := &arkv1.Conviction{
		Id:        conviction.GetID(),
		Type:      convictionType,
		CreatedAt: conviction.GetCreatedAt().Unix(),
		ExpiresAt: expiresAt,
		CrimeType: arkv1.CrimeType(conviction.GetCrime().Type),
		RoundId:   conviction.GetCrime().RoundID,
		Reason:    conviction.GetCrime().Reason,
		Pardoned:  conviction.IsPardoned(),
	}

	if scriptConviction, ok := conviction.(domain.ScriptConviction); ok {
		protoConviction.Script = scriptConviction.Script
	}

	return protoConviction, nil
}

func parseTime(t string) (*time.Time, error) {
	if len(t) <= 0 {
		return nil, nil
	}
	tm, err := time.Parse(time.RFC3339, t)
	if err != nil {
		return nil, err
	}
	return &tm, nil
}

func parseMacaroon(mac string) (string, []byte, []bakery.Op, error) {
	// Decode hex to bytes.
	buf, err := hex.DecodeString(mac)
	if err != nil {
		return "", nil, nil, fmt.Errorf("macaroon must be in hex format")
	}

	// Unmarshal the macaroon.
	m := &macaroon.Macaroon{}
	if err := m.UnmarshalBinary(buf); err != nil {
		return "", nil, nil, fmt.Errorf("failed to unmarshal macaroon: %s", err)
	}

	// Unmarshal the macaroon id.
	macId := &macaroonpb.MacaroonId{}
	if err := macId.UnmarshalBinary(m.Id()[1:]); err != nil {
		return "", nil, nil, fmt.Errorf("failed to unmarshal macaroon id: %s", err)
	}

	// Extract rootkeey id and ops from macaroon id.
	ops := make([]bakery.Op, 0, len(macId.GetOps()))
	for _, op := range macId.GetOps() {
		for _, action := range op.GetActions() {
			ops = append(ops, bakery.Op{
				Entity: op.GetEntity(),
				Action: action,
			})
		}
	}
	return mac, macId.GetStorageId(), ops, nil
}

func parseFees(fees *arkv1.IntentFees) (*domain.BatchFeesUpdate, error) {
	if fees == nil {
		return nil, fmt.Errorf("missing batch fees")
	}

	var offchainInputFee, offchainOutputFee, onchainInputFee, onchainOutputFee *string
	if program := fees.GetOffchainInputFee(); len(program) > 0 {
		offchainInputFee = &program
	}
	if program := fees.GetOnchainInputFee(); len(program) > 0 {
		onchainInputFee = &program
	}
	if program := fees.GetOffchainOutputFee(); len(program) > 0 {
		offchainOutputFee = &program
	}
	if program := fees.GetOnchainOutputFee(); len(program) > 0 {
		onchainOutputFee = &program
	}
	return &domain.BatchFeesUpdate{
		OffchainInputFee:  offchainInputFee,
		OffchainOutputFee: offchainOutputFee,
		OnchainInputFee:   onchainInputFee,
		OnchainOutputFee:  onchainOutputFee,
	}, nil
}

func parseSettings(settings *arkv1.Settings) (*domain.SettingsUpdate, error) {
	if settings == nil {
		return nil, fmt.Errorf("missing settings")
	}

	vtxoNoCsvValidationCutoffDate, err := parseTime(settings.GetVtxoNoCsvValidationCutoffDate())
	if err != nil {
		return nil, fmt.Errorf("failed to ")
	}

	var (
		banThreshold, maxTxWeight, maxOpReturnOutputs *uint64
		batchMinParticipants, batchMaxParticipants,
		vtxoMinAmount, vtxoMaxAmount, utxoMinAmount, utxoMaxAmount *int64
		assetTxMaxWeightRatio                            *float32
		noteUriPrefix                                    *string
		buildVersionHeader                               *string
		buildVersionHeaderRequired, digestHeaderRequired *bool
	)
	if settings.BanThreshold != nil {
		t := uint64(settings.GetBanThreshold())
		banThreshold = &t
	}
	if settings.MaxTxWeight != nil {
		t := uint64(settings.GetMaxTxWeight())
		maxTxWeight = &t
	}
	if settings.MaxOpReturnOutputs != nil {
		t := uint64(settings.GetMaxOpReturnOutputs())
		maxOpReturnOutputs = &t
	}
	if settings.RoundMinParticipantsCount != nil {
		t := int64(settings.GetRoundMinParticipantsCount())
		batchMinParticipants = &t
	}
	if settings.RoundMaxParticipantsCount != nil {
		t := int64(settings.GetRoundMaxParticipantsCount())
		batchMaxParticipants = &t
	}
	if settings.VtxoMinAmount != nil {
		t := int64(settings.GetVtxoMinAmount())
		vtxoMinAmount = &t
	}
	if settings.VtxoMaxAmount != nil {
		t := int64(settings.GetVtxoMaxAmount())
		vtxoMaxAmount = &t
	}
	if settings.UtxoMinAmount != nil {
		t := int64(settings.GetUtxoMinAmount())
		utxoMinAmount = &t
	}
	if settings.UtxoMaxAmount != nil {
		t := int64(settings.GetUtxoMaxAmount())
		utxoMaxAmount = &t
	}
	if settings.AssetTxMaxWeightRatio != nil {
		t := float32(settings.GetAssetTxMaxWeightRatio())
		assetTxMaxWeightRatio = &t
	}
	if settings.NoteUriPrefix != nil {
		t := settings.GetNoteUriPrefix()
		noteUriPrefix = &t
	}
	if settings.BuildVersionHeader != nil {
		t := settings.GetBuildVersionHeader()
		buildVersionHeader = &t
	}
	if settings.BuildVersionHeaderRequired != nil {
		t := settings.GetBuildVersionHeaderRequired()
		buildVersionHeaderRequired = &t
	}
	if settings.DigestHeaderRequired != nil {
		t := settings.GetDigestHeaderRequired()
		digestHeaderRequired = &t
	}
	var walletAddr *string
	if settings.WalletAddr != nil {
		t := settings.GetWalletAddr()
		walletAddr = &t
	}
	// wallet_fallback_addrs is a repeated field with no presence, so an empty list
	// is indistinguishable from "not provided" and is treated as no-change. The
	// fallback list can be replaced but not cleared via the API; clear it by
	// reconfiguring env and re-seeding.
	var walletFallbackAddrs *[]string
	if len(settings.WalletFallbackAddrs) > 0 {
		t := settings.GetWalletFallbackAddrs()
		walletFallbackAddrs = &t
	}

	return &domain.SettingsUpdate{
		SessionDuration:               parseDuration(settings.SessionDuration),
		UnrolledVtxoMinExpiryMargin:   parseDuration(settings.UnrolledVtxoMinExpiryMargin),
		BanThreshold:                  banThreshold,
		BanDuration:                   parseDuration(settings.BanDuration),
		UnilateralExitDelay:           parseLocktime(settings.UnilateralExitDelay),
		PublicUnilateralExitDelay:     parseLocktime(settings.PublicUnilateralExitDelay),
		CheckpointExitDelay:           parseLocktime(settings.CheckpointExitDelay),
		BoardingExitDelay:             parseLocktime(settings.BoardingExitDelay),
		VtxoTreeExpiry:                parseLocktime(settings.VtxoTreeExpiry),
		RoundMinParticipantsCount:     batchMinParticipants,
		RoundMaxParticipantsCount:     batchMaxParticipants,
		VtxoMinAmount:                 vtxoMinAmount,
		VtxoMaxAmount:                 vtxoMaxAmount,
		UtxoMinAmount:                 utxoMinAmount,
		UtxoMaxAmount:                 utxoMaxAmount,
		SettlementMinExpiryGap:        parseDuration(settings.SettlementMinExpiryGap),
		VtxoNoCsvValidationCutoffDate: vtxoNoCsvValidationCutoffDate,
		MaxTxWeight:                   maxTxWeight,
		MaxOpReturnOutputs:            maxOpReturnOutputs,
		AssetTxMaxWeightRatio:         assetTxMaxWeightRatio,
		NoteUriPrefix:                 noteUriPrefix,
		BuildVersionHeader:            buildVersionHeader,
		BuildVersionHeaderRequired:    buildVersionHeaderRequired,
		DigestHeaderRequired:          digestHeaderRequired,
		WalletAddr:                    walletAddr,
		WalletFallbackAddrs:           walletFallbackAddrs,
	}, nil
}

func parseDuration(duration *int64) *time.Duration {
	if duration == nil {
		return nil
	}
	t := time.Duration(*duration) * time.Second
	return &t
}

func formatDuration(duration time.Duration) *int64 {
	t := int64(duration.Seconds())
	return &t
}

func parseLocktime(delay *int64) *arklib.RelativeLocktime {
	if delay == nil {
		return nil
	}
	t, _ := arklib.ParseRelativeLocktime(uint32(*delay))
	return &t
}

func formatLocktime(delay arklib.RelativeLocktime) *int64 {
	t := delay.Seconds()
	return &t
}

func formatUint64(val uint64) *int64 {
	t := int64(val)
	return &t
}

func formatTime(tm time.Time) *string {
	if tm.IsZero() {
		return nil
	}
	t := tm.Format(time.RFC3339)
	return &t
}
