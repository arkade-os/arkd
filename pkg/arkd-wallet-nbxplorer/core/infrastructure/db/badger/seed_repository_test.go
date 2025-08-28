package badgerdb_test

import (
	"context"
	"testing"

	badgerdb "github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/infrastructure/db/badger"
	"github.com/arkade-os/arkd/pkg/arkd-wallet-nbxplorer/core/ports"
	"github.com/stretchr/testify/require"
)

func TestNewSeedRepository(t *testing.T) {
	tests := []struct {
		name    string
		baseDir string
		wantErr bool
	}{
		{
			name:    "in-memory database",
			baseDir: "",
			wantErr: false,
		},
		{
			name:    "file-based database",
			baseDir: t.TempDir(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := badgerdb.NewSeedRepository(tt.baseDir, nil)
			if tt.wantErr {
				require.Error(t, err)
				require.Nil(t, repo)
			} else {
				require.NoError(t, err)
				require.NotNil(t, repo)
				require.Implements(t, (*ports.SeedRepository)(nil), repo)
			}
		})
	}
}

func TestSeedRepository_IsInitialized(t *testing.T) {
	repo, err := badgerdb.NewSeedRepository("", nil)
	require.NoError(t, err)
	require.NotNil(t, repo)

	ctx := context.Background()

	// Initially should not be initialized
	initialized := repo.IsInitialized(ctx)
	require.False(t, initialized)

	// Add encrypted seed
	seed := []byte("test_encrypted_seed")
	err = repo.AddEncryptedSeed(ctx, seed)
	require.NoError(t, err)

	// Should be initialized after adding seed
	initialized = repo.IsInitialized(ctx)
	require.True(t, initialized)

	// Test with empty seed - should not be initialized
	emptySeed := []byte{}
	err = repo.AddEncryptedSeed(ctx, emptySeed)
	require.NoError(t, err)

	initialized = repo.IsInitialized(ctx)
	require.False(t, initialized)
}

func TestSeedRepository_GetEncryptedSeed(t *testing.T) {
	repo, err := badgerdb.NewSeedRepository("", nil)
	require.NoError(t, err)
	require.NotNil(t, repo)

	ctx := context.Background()

	// Should return error when seed doesn't exist
	seed, err := repo.GetEncryptedSeed(ctx)
	require.Error(t, err)
	require.Nil(t, seed)
	require.Contains(t, err.Error(), "encrypted seed not found")

	// Add encrypted seed
	testSeed := []byte("test_encrypted_seed_data")
	err = repo.AddEncryptedSeed(ctx, testSeed)
	require.NoError(t, err)

	// Should return the seed after adding it
	seed, err = repo.GetEncryptedSeed(ctx)
	require.NoError(t, err)
	require.Equal(t, testSeed, seed)

	// Test retrieving empty seed
	emptySeed := []byte{}
	err = repo.AddEncryptedSeed(ctx, emptySeed)
	require.NoError(t, err)

	retrievedSeed, err := repo.GetEncryptedSeed(ctx)
	require.NoError(t, err)
	require.Len(t, retrievedSeed, 0)
}

func TestSeedRepository_AddEncryptedSeed(t *testing.T) {
	repo, err := badgerdb.NewSeedRepository("", nil)
	require.NoError(t, err)
	require.NotNil(t, repo)

	ctx := context.Background()

	// Test adding seed
	testSeed := []byte("test_encrypted_seed_data")
	err = repo.AddEncryptedSeed(ctx, testSeed)
	require.NoError(t, err)

	// Verify seed was added
	retrievedSeed, err := repo.GetEncryptedSeed(ctx)
	require.NoError(t, err)
	require.Equal(t, testSeed, retrievedSeed)

	// Test updating existing seed
	updatedSeed := []byte("updated_encrypted_seed_data")
	err = repo.AddEncryptedSeed(ctx, updatedSeed)
	require.NoError(t, err)

	// Verify seed was updated
	retrievedSeed, err = repo.GetEncryptedSeed(ctx)
	require.NoError(t, err)
	require.Equal(t, updatedSeed, retrievedSeed)

	// Test adding empty seed
	emptySeed := []byte{}
	err = repo.AddEncryptedSeed(ctx, emptySeed)
	require.NoError(t, err)

	// Verify empty seed was stored
	retrievedSeed, err = repo.GetEncryptedSeed(ctx)
	require.NoError(t, err)
	require.Len(t, retrievedSeed, 0)
}
