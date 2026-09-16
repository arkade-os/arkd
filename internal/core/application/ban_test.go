package application

import (
	"context"
	"testing"

	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/arkade-os/arkd/internal/core/ports"
	"github.com/arkade-os/arkd/pkg/errors"
	"github.com/stretchr/testify/require"
)

func TestCheckIfBanned(t *testing.T) {
	ctx := t.Context()
	candidates := []banCandidate{{
		outpoint: domain.Outpoint{Txid: "aa", VOut: 0}, script: mockOutputScript{0x51},
	}}

	t.Run("huge threshold does not ban a script with no convictions", func(t *testing.T) {
		// A negative ban threshold stored before validation existed reaches us as a
		// huge uint64: it must not wrap and ban everyone.
		svc := &service{repoManager: &mockedBanRepoManager{}}
		bans, err := svc.checkIfBanned(ctx, ^uint64(0), candidates)
		require.NoError(t, err)
		require.Empty(t, bans)
		require.Nil(t, bans)
	})

	t.Run("threshold reached bans the script", func(t *testing.T) {
		svc := &service{repoManager: &mockedBanRepoManager{
			convictions: []domain.ScriptConviction{{}, {}},
		}}
		bans, err := svc.checkIfBanned(ctx, 2, candidates)
		require.NoError(t, err)
		require.NotNil(t, bans)
		require.Len(t, bans, 1)
		require.Equal(t, "51", bans[0].script)
		require.Len(t, bans[0].convictions, 2)
	})

	t.Run("zero threshold disables banning", func(t *testing.T) {
		svc := &service{repoManager: &mockedBanRepoManager{
			convictions: []domain.ScriptConviction{{}, {}},
		}}
		bans, err := svc.checkIfBanned(ctx, 0, candidates)
		require.NoError(t, err)
		require.Empty(t, bans)
		require.Nil(t, bans)
	})

	t.Run("bans only scripts at the threshold, reading each once in input order", func(t *testing.T) {
		// The scripts are given out of sorted order, so the result has to follow
		// the input rather than happen to match a sort.
		a, b, c := mockOutputScript{0x53}, mockOutputScript{0x52}, mockOutputScript{0x51}
		bConvictions := []domain.ScriptConviction{
			testScriptConviction("b1"), testScriptConviction("b2"),
		}
		cConvictions := []domain.ScriptConviction{
			testScriptConviction("c1"), testScriptConviction("c2"), testScriptConviction("c3"),
		}

		var queried [][]string
		repos := &mockedRepoManager{}
		repos.On("Convictions").Return(convictionRepoStub{
			convictions: map[string][]domain.ScriptConviction{
				"53": {testScriptConviction("a1")},
				"52": bConvictions,
				"51": cConvictions,
			},
			queried: &queried,
		})
		svc := &service{repoManager: repos}

		bans, err := svc.checkIfBanned(ctx, 2, []banCandidate{
			{outpoint: domain.Outpoint{Txid: "aa", VOut: 0}, script: a},
			{outpoint: domain.Outpoint{Txid: "bb", VOut: 1}, script: a},
			{outpoint: domain.Outpoint{Txid: "cc", VOut: 2}, script: b},
			{outpoint: domain.Outpoint{Txid: "dd", VOut: 3}, script: c},
		})
		require.NoError(t, err)
		require.Equal(t, [][]string{{"53", "52", "51"}}, queried)
		require.Equal(t, []scriptBan{
			{
				script:      "52",
				outpoints:   []string{"cc:2"},
				convictions: []string{bConvictions[0].String(), bConvictions[1].String()},
			},
			{
				script:    "51",
				outpoints: []string{"dd:3"},
				convictions: []string{
					cConvictions[0].String(), cConvictions[1].String(), cConvictions[2].String(),
				},
			},
		}, bans)
	})

	t.Run("banned error names each script with its convictions and inputs", func(t *testing.T) {
		appErr := vtxoBannedError([]scriptBan{
			{
				script:      "b",
				outpoints:   []string{"aa:0", "cc:2"},
				convictions: []string{"conviction 1"},
			},
			{
				script:      "a",
				outpoints:   []string{"bb:1"},
				convictions: []string{"conviction 2", "conviction 3"},
			},
		})
		require.Equal(t, errors.VTXO_BANNED.Code, appErr.Code())
		require.Equal(t,
			"VTXO_BANNED (29): script b is banned by 1 convictions: conviction 1; "+
				"script a is banned by 2 convictions: conviction 2, conviction 3",
			appErr.Error(),
		)
		require.Equal(t, "aa:0", appErr.Metadata()["vtxo_outpoint"])
		require.Equal(t, "[aa:0 cc:2 bb:1]", appErr.Metadata()["vtxo_outpoints"])
		require.Equal(t, "[b a]", appErr.Metadata()["scripts"])
	})
}

type mockOutputScript []byte

func (s mockOutputScript) OutputScript() ([]byte, error) {
	return s, nil
}

type mockedBanRepoManager struct {
	ports.RepoManager // unimplemented methods panic on call
	convictions       []domain.ScriptConviction
}

func (m *mockedBanRepoManager) Convictions() domain.ConvictionRepository {
	return &mockedConvictionRepo{convictions: m.convictions}
}

type mockedConvictionRepo struct {
	domain.ConvictionRepository // unimplemented methods panic on call
	convictions                 []domain.ScriptConviction
}

func (m *mockedConvictionRepo) GetActiveScriptsConvictions(
	ctx context.Context, scripts []string,
) (map[string][]domain.ScriptConviction, error) {
	return map[string][]domain.ScriptConviction{scripts[0]: m.convictions}, nil
}

// convictionRepoStub answers from the convictions it holds by script, records
// the scripts of every query, and fails every query with err when set.
type convictionRepoStub struct {
	domain.ConvictionRepository // unimplemented methods panic on call
	convictions                 map[string][]domain.ScriptConviction
	queried                     *[][]string
	err                         error
}

func (r convictionRepoStub) GetActiveScriptsConvictions(
	_ context.Context, scripts []string,
) (map[string][]domain.ScriptConviction, error) {
	if r.queried != nil {
		*r.queried = append(*r.queried, scripts)
	}
	if r.err != nil {
		return nil, r.err
	}
	found := make(map[string][]domain.ScriptConviction)
	for _, script := range scripts {
		if convictions, ok := r.convictions[script]; ok {
			found[script] = convictions
		}
	}
	return found, nil
}

func testScriptConviction(reason string) domain.ScriptConviction {
	return domain.ScriptConviction{
		BaseConviction: domain.BaseConviction{Crime: domain.Crime{Reason: reason}},
	}
}
