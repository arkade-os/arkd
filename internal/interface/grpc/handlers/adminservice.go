package handlers

import (
	"context"
	"fmt"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type adminHandler struct {
	adminService application.AdminService

	noteUriPrefix string
}

func NewAdminHandler(
	adminService application.AdminService, noteUriPrefix string,
) arkv1.AdminServiceServer {
	return &adminHandler{adminService, noteUriPrefix}
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

	if startAfter < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid after (must be >= 0)")
	}

	if startBefore < 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid before (must be >= 0)")
	}

	if startAfter >= startBefore {
		return nil, status.Error(codes.InvalidArgument, "invalid range")
	}

	rounds, err := a.adminService.GetRounds(ctx, startAfter, startBefore)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	return &arkv1.GetRoundsResponse{Rounds: rounds}, nil
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
				Txid:        output.TxId,
				Vout:        output.Vout,
				ScheduledAt: output.ScheduledAt,
				Amount:      convertSatsToBTCStr(output.Amount),
			})
		}

		sweeps = append(sweeps, &arkv1.ScheduledSweep{
			RoundId: sweep.RoundId,
			Outputs: outputs,
		})
	}

	return &arkv1.GetScheduledSweepResponse{Sweeps: sweeps}, nil
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

func (a *adminHandler) GetMarketHourConfig(
	ctx context.Context, _ *arkv1.GetMarketHourConfigRequest,
) (*arkv1.GetMarketHourConfigResponse, error) {
	marketHour, err := a.adminService.GetMarketHourConfig(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	var config *arkv1.MarketHourConfig
	if marketHour != nil {
		config = &arkv1.MarketHourConfig{
			StartTime:     marketHour.StartTime.Unix(),
			EndTime:       marketHour.EndTime.Unix(),
			Period:        int64(marketHour.Period.Minutes()),
			RoundInterval: int64(marketHour.RoundInterval.Seconds()),
		}
	}

	return &arkv1.GetMarketHourConfigResponse{Config: config}, nil
}

func (a *adminHandler) UpdateMarketHourConfig(
	ctx context.Context, req *arkv1.UpdateMarketHourConfigRequest,
) (*arkv1.UpdateMarketHourConfigResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "missing market hour config")
	}

	if err := a.adminService.UpdateMarketHourConfig(
		ctx,
		time.Unix(req.GetConfig().GetStartTime(), 0),
		time.Unix(req.GetConfig().GetEndTime(), 0),
		time.Duration(req.GetConfig().GetPeriod())*time.Minute,
		time.Duration(req.GetConfig().GetRoundInterval())*time.Second,
	); err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &arkv1.UpdateMarketHourConfigResponse{}, nil
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

func (a *adminHandler) GetConviction(
	ctx context.Context, req *arkv1.GetConvictionRequest,
) (*arkv1.GetConvictionResponse, error) {
	id := req.GetId()
	if len(id) == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing conviction id")
	}

	conviction, err := a.adminService.GetConviction(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%s", err.Error())
	}

	protoConviction, err := convertConvictionToProto(conviction)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert conviction: %s", err.Error())
	}

	return &arkv1.GetConvictionResponse{Conviction: protoConviction}, nil
}

func (a *adminHandler) GetConvictions(
	ctx context.Context, req *arkv1.GetConvictionsRequest,
) (*arkv1.GetConvictionsResponse, error) {
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

	return &arkv1.GetConvictionsResponse{Convictions: protoConvictions}, nil
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
