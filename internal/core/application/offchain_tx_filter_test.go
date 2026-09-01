package application_test

import (
	"testing"

	"github.com/arkade-os/arkd/internal/core/application"
	"github.com/arkade-os/arkd/internal/core/domain"
	"github.com/stretchr/testify/require"
)

func TestExtractOffchainTxFilter(t *testing.T) {
	t.Parallel()

	t.Run("empty expression yields zero filter", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter("")
		require.NoError(t, err)
		require.Equal(t, domain.OffchainTxFilter{}, got)
	})

	t.Run("has(tx.extension)", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter("has(tx.extension)")
		require.NoError(t, err)
		require.True(t, got.WithExtension)
		require.Empty(t, got.WithPacket)
	})

	t.Run("hasPacket implies packet entry", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"hasPacket(tx.extension, 66)",
		)
		require.NoError(t, err)
		require.Contains(t, got.WithPacket, 66)
		require.Equal(t, "", got.WithPacket[66])
	})

	t.Run("equality predicate populates payload", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"tx.extension[66] == 'deadbeef'",
		)
		require.NoError(t, err)
		require.Equal(t, "deadbeef", got.WithPacket[66])
	})

	t.Run("flat AND combines predicates", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"has(tx.extension) && hasPacket(tx.extension, 1) && tx.extension[2] == 'abcd'",
		)
		require.NoError(t, err)
		require.True(t, got.WithExtension)
		require.Contains(t, got.WithPacket, 1)
		require.Equal(t, "", got.WithPacket[1])
		require.Equal(t, "abcd", got.WithPacket[2])
	})

	t.Run("contains predicate populates substring", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"tx.extension[66].contains('deadbeef')",
		)
		require.NoError(t, err)
		require.Equal(t, []string{"deadbeef"}, got.WithPacketContains[66])
	})

	t.Run("multiple contains on same packet accumulate", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"tx.extension[1].contains('aa') && tx.extension[1].contains('bb')",
		)
		require.NoError(t, err)
		require.Equal(t, []string{"aa", "bb"}, got.WithPacketContains[1])
	})

	t.Run("contains combines with hasPacket and equality", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"hasPacket(tx.extension, 1) && tx.extension[2] == 'abcd' && tx.extension[3].contains('ef')",
		)
		require.NoError(t, err)
		require.Contains(t, got.WithPacket, 1)
		require.Equal(t, "abcd", got.WithPacket[2])
		require.Equal(t, []string{"ef"}, got.WithPacketContains[3])
	})

	t.Run("non-hex contains payload is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"tx.extension[1].contains('not_hex')",
		)
		require.Error(t, err)
	})

	t.Run("contains on non-extension target is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"'deadbeef'.contains('ad')",
		)
		require.Error(t, err)
	})

	t.Run("OR is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"hasPacket(tx.extension, 1) || hasPacket(tx.extension, 2)",
		)
		require.Error(t, err)
	})

	t.Run("non-hex equality payload is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"tx.extension[1] == 'not_hex'",
		)
		require.Error(t, err)
	})

	t.Run("compile error is surfaced", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter("tx.extension[")
		require.Error(t, err)
	})

	t.Run("expression over the length cap is rejected", func(t *testing.T) {
		// "has(tx.extension)" repeated past the cap. The cap is enforced
		// before CEL parsing, so a syntactically valid-but-huge
		// expression is still rejected.
		const lead = "has(tx.extension) && "
		expr := lead
		for len(expr) <= application.MaxFilterExpressionLength {
			expr += lead
		}
		expr += "has(tx.extension)"
		_, err := application.ExtractOffchainTxFilter(expr)
		require.Error(t, err)
		require.Contains(t, err.Error(), "too long")
	})

	t.Run("literal on left of equality is accepted", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"'cafebabe' == tx.extension[7]",
		)
		require.NoError(t, err)
		require.Equal(t, "cafebabe", got.WithPacket[7])
	})

	t.Run("conflicting payloads for same packet are rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"tx.extension[1] == 'aa' && tx.extension[1] == 'bb'",
		)
		require.Error(t, err)
	})

	t.Run("hasPacket then equality on same packet merges to payload", func(t *testing.T) {
		got, err := application.ExtractOffchainTxFilter(
			"hasPacket(tx.extension, 9) && tx.extension[9] == 'aa'",
		)
		require.NoError(t, err)
		require.Equal(t, "aa", got.WithPacket[9])
	})

	t.Run("not-equals is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"tx.extension[1] != 'aa'",
		)
		require.Error(t, err)
	})

	t.Run("size() is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter(
			"has(tx.extension) && size(tx.extension) > 1",
		)
		require.Error(t, err)
	})

	t.Run("presence test on non-extension field is rejected", func(t *testing.T) {
		_, err := application.ExtractOffchainTxFilter("has(tx.unknown)")
		require.Error(t, err)
	})
}

func TestOffchainTxFilterValidate(t *testing.T) {
	t.Parallel()

	t.Run("zero filter is valid", func(t *testing.T) {
		require.NoError(t, domain.OffchainTxFilter{}.Validate())
	})

	t.Run("after only is valid", func(t *testing.T) {
		require.NoError(t, domain.OffchainTxFilter{WithAfterDate: 10}.Validate())
	})

	t.Run("before only is valid", func(t *testing.T) {
		require.NoError(t, domain.OffchainTxFilter{WithBeforeDate: 20}.Validate())
	})

	t.Run("within is valid when before > after", func(t *testing.T) {
		require.NoError(t, domain.OffchainTxFilter{
			WithAfterDate: 5, WithBeforeDate: 10,
		}.Validate())
	})

	t.Run("within is valid when before == after", func(t *testing.T) {
		require.NoError(t, domain.OffchainTxFilter{
			WithAfterDate: 10, WithBeforeDate: 10,
		}.Validate())
	})

	t.Run("within is rejected when before < after", func(t *testing.T) {
		require.Error(t, domain.OffchainTxFilter{
			WithAfterDate: 10, WithBeforeDate: 5,
		}.Validate())
	})

	t.Run("negative bounds are rejected", func(t *testing.T) {
		require.Error(t, domain.OffchainTxFilter{WithAfterDate: -1}.Validate())
		require.Error(t, domain.OffchainTxFilter{WithBeforeDate: -1}.Validate())
	})
}
