package grpcservice

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/arkade-os/arkd/internal/interface/grpc/permissions"
	"github.com/arkade-os/arkd/pkg/kvdb"
	"github.com/arkade-os/arkd/pkg/macaroons"
	log "github.com/sirupsen/logrus"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

var (
	superUserMacaroonFile = "superuser.macaroon"
	adminMacaroonFile     = "admin.macaroon"
	operatorMacaroonFile  = "operator.macaroon"
	unlockerMacaroonFile  = "unlocker.macaroon"
	roMacaroonFile        = "readonly.macaroon"

	macFiles = map[string][]bakery.Op{
		superUserMacaroonFile: permissions.SuperUserPermissions(),
		adminMacaroonFile:     permissions.AdminPermissions(),
		operatorMacaroonFile:  permissions.OperatorPermissions(),
		unlockerMacaroonFile:  permissions.UnlockerPermissions(),
		roMacaroonFile:        permissions.ReadOnlyPermissions(),
	}
)

// genMacaroons generates the macaroon files if they don't already exist.
func genMacaroons(
	ctx context.Context, svc *macaroons.Service, datadir string,
) (bool, error) {
	// Check the macaroons to (re-)generate.
	macaroonsToGenerate := make(map[string][]bakery.Op)
	for filename, ops := range macFiles {
		if pathExists(filepath.Join(datadir, filename)) {
			continue
		}
		macaroonsToGenerate[filename] = ops
	}

	// Don't do anything if all macaroons already exist.
	if len(macaroonsToGenerate) == 0 {
		return false, nil
	}

	// Create the datadir if it doesn't exist.
	if err := makeDirectoryIfNotExists(datadir); err != nil {
		return false, err
	}

	// Create the macaroon files.
	for macFilename, macPermissions := range macaroonsToGenerate {
		macBytes, err := svc.BakeMacaroon(ctx, macPermissions, strings.Split(macFilename, ".")[0])
		if err != nil {
			return false, err
		}
		macFile := filepath.Join(datadir, macFilename)
		perms := fs.FileMode(0644)
		if macFilename == adminMacaroonFile || macFilename == superUserMacaroonFile {
			perms = fs.FileMode(0600)
		}
		if err := os.WriteFile(macFile, macBytes, perms); err != nil {
			// nolint:all
			os.Remove(macFile)
			return false, err
		}
	}

	return true, nil
}

func makeDirectoryIfNotExists(path string) error {
	if pathExists(path) {
		return nil
	}
	return os.MkdirAll(path, os.ModeDir|0755)
}

func pathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// newMacaroonService creates (or opens) the macaroon database in the service
// datadir and returns a macaroon service backed by it, along with the database
// handle. Closing the service only zeroes the in-memory encryption key, so the
// caller owns the handle and must close it on shutdown. Both are nil if
// macaroons are disabled.
func newMacaroonService(svcConfig Config) (*macaroons.Service, kvdb.Backend, error) {
	if svcConfig.NoMacaroons {
		return nil, nil, nil
	}

	macaroonDB, err := kvdb.Create(
		kvdb.BoltBackendName, filepath.Join(svcConfig.Datadir, macaroonsDbFile),
		true, kvdb.DefaultDBTimeout, false,
	)
	if err != nil {
		return nil, nil, err
	}

	keyStore, err := macaroons.NewRootKeyStorage(macaroonDB)
	if err != nil {
		closeMacaroonStore(nil, macaroonDB)
		return nil, nil, err
	}

	svc, err := macaroons.NewService(
		keyStore, macaroonsLocation, false, macaroons.IPLockChecker,
	)
	if err != nil {
		closeMacaroonStore(nil, macaroonDB)
		return nil, nil, err
	}

	return svc, macaroonDB, nil
}

// closeMacaroonStore releases a macaroon service and the database handle it was
// built on, logging any failure. Closing the service only zeroes its in-memory
// keys, so the database has to be closed separately to release the bolt file
// lock. Either argument may be nil.
func closeMacaroonStore(svc *macaroons.Service, db kvdb.Backend) {
	if svc != nil {
		if err := svc.Close(); err != nil {
			log.Errorf("failed to close macaroon service: %s", err)
		}
	}
	if db != nil {
		if err := db.Close(); err != nil {
			log.Errorf("failed to close macaroon db: %s", err)
		}
	}
}
