package application

import (
	"testing"
	"time"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/ark-lib/batchtrigger"
	"github.com/stretchr/testify/require"
)

func TestAggregateIntentTriggerData(t *testing.T) {
	tests := []struct {
		name                       string
		intents                    []ports.TimedIntent
		wantBoardingInputsCount    int64
		wantTotalBoardingAmount    uint64
		wantTotalIntentFees        uint64
	}{
		{
			name:                    "empty intents",
			intents:                 nil,
			wantBoardingInputsCount: 0,
			wantTotalBoardingAmount: 0,
			wantTotalIntentFees:     0,
		},
		{
			name: "single intent with boarding inputs and positive fee",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs: []domain.Vtxo{
							{Amount: 1000},
							{Amount: 500},
						},
						Receivers: []domain.Receiver{
							{Amount: 800},
							{Amount: 600},
						},
					},
					BoardingInputs: []ports.BoardingInput{
						{Amount: 200},
						{Amount: 300},
					},
				},
			},
			wantBoardingInputsCount: 2,
			wantTotalBoardingAmount: 500,
			// inputs: 1500 vtxo + 500 boarding = 2000; outputs: 1400; fee = 600
			wantTotalIntentFees: 600,
		},
		{
			name: "intent with no boarding and no fee (inputs == outputs)",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 1000}},
						Receivers: []domain.Receiver{{Amount: 1000}},
					},
				},
			},
			wantBoardingInputsCount: 0,
			wantTotalBoardingAmount: 0,
			wantTotalIntentFees:     0,
		},
		{
			name: "intent where outputs exceed inputs is treated as zero fee",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 100}},
						Receivers: []domain.Receiver{{Amount: 200}},
					},
				},
			},
			wantBoardingInputsCount: 0,
			wantTotalBoardingAmount: 0,
			wantTotalIntentFees:     0,
		},
		{
			name: "multiple intents are summed",
			intents: []ports.TimedIntent{
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 1000}},
						Receivers: []domain.Receiver{{Amount: 900}},
					},
					BoardingInputs: []ports.BoardingInput{{Amount: 50}},
				},
				{
					Intent: domain.Intent{
						Inputs:    []domain.Vtxo{{Amount: 2000}},
						Receivers: []domain.Receiver{{Amount: 1800}},
					},
					BoardingInputs: []ports.BoardingInput{
						{Amount: 100},
						{Amount: 100},
					},
				},
			},
			wantBoardingInputsCount: 3,
			wantTotalBoardingAmount: 250,
			// intent 1: 1000+50 - 900 = 150
			// intent 2: 2000+200 - 1800 = 400
			wantTotalIntentFees: 550,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotCount, gotBoarding, gotFees := aggregateIntentTriggerData(tt.intents)
			require.Equal(t, tt.wantBoardingInputsCount, gotCount, "boarding inputs count")
			require.Equal(t, tt.wantTotalBoardingAmount, gotBoarding, "total boarding amount")
			require.Equal(t, tt.wantTotalIntentFees, gotFees, "total intent fees")
		})
	}
}

func TestEvalBatchTrigger(t *testing.T) {
	tests := []struct {
		name    string
		program string
		ctx     batchtrigger.Context
		want    bool
	}{
		{
			name:    "nil trigger always permits",
			program: "",
			want:    true,
		},
		{
			name:    "true literal permits",
			program: "true",
			want:    true,
		},
		{
			name:    "false literal denies",
			program: "false",
			want:    false,
		},
		{
			name:    "intent count gate satisfied",
			program: "intents_count >= 2.0",
			ctx:     batchtrigger.Context{IntentsCount: 5},
			want:    true,
		},
		{
			name:    "intent count gate unsatisfied",
			program: "intents_count >= 2.0",
			ctx:     batchtrigger.Context{IntentsCount: 1},
			want:    false,
		},
		{
			name:    "fee revenue gate satisfied",
			program: "total_intent_fees >= 500.0",
			ctx:     batchtrigger.Context{TotalIntentFees: 1000},
			want:    true,
		},
		{
			name: "issue 1045 example: many intents, low fees",
			program: "intents_count > 1.0 && " +
				"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
			ctx: batchtrigger.Context{
				IntentsCount:   3,
				CurrentFeerate: 1,
			},
			want: true,
		},
		{
			name: "issue 1045 example: many intents, high fees, but stale",
			program: "intents_count > 1.0 && " +
				"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
			ctx: batchtrigger.Context{
				IntentsCount:       3,
				CurrentFeerate:     50,
				TimeSinceLastBatch: 7200,
			},
			want: true,
		},
		{
			name: "issue 1045 example: many intents, high fees, recent",
			program: "intents_count > 1.0 && " +
				"(current_feerate <= 2.0 || time_since_last_batch >= 3600.0)",
			ctx: batchtrigger.Context{
				IntentsCount:       3,
				CurrentFeerate:     50,
				TimeSinceLastBatch: 60,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := batchtrigger.New(tt.program)
			require.NoError(t, err)

			s := &service{batchTrigger: tr}
			require.Equal(t, tt.want, s.evalBatchTrigger(tt.ctx))
		})
	}
}

func TestEvalBatchTriggerNilFailsOpen(t *testing.T) {
	// A nil service.batchTrigger must permit; the context value is ignored.
	s := &service{}
	require.True(t, s.evalBatchTrigger(batchtrigger.Context{}))
	require.True(t, s.evalBatchTrigger(batchtrigger.Context{IntentsCount: 0}))
}

func TestLastBatchAtRoundtrip(t *testing.T) {
	// Sanity check that the atomic counter we use to derive
	// time_since_last_batch behaves as expected: zero until set, monotonic
	// once written.
	s := &service{}
	require.Equal(t, int64(0), s.lastBatchAt.Load())

	now := time.Now().Unix()
	s.lastBatchAt.Store(now)
	require.Equal(t, now, s.lastBatchAt.Load())
}
