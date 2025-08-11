package handlers

import (
	"context"
	"fmt"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/core/application"
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
		return nil, status.Errorf(codes.Internal, err.Error())
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
		return nil, status.Errorf(codes.Internal, err.Error())
	}

	return &arkv1.GetRoundsResponse{Rounds: rounds}, nil
}

func (a *adminHandler) GetScheduledSweep(
	ctx context.Context, _ *arkv1.GetScheduledSweepRequest,
) (*arkv1.GetScheduledSweepResponse, error) {
	scheduledSweeps, err := a.adminService.GetScheduledSweeps(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, err.Error())
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
		return nil, status.Errorf(codes.Internal, err.Error())
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
