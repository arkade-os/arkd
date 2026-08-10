package permissions_test

import (
	"fmt"
	"testing"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	"github.com/arkade-os/arkd/internal/interface/grpc/permissions"
	"github.com/stretchr/testify/require"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

// consoleMethods is every RPC the read-only operator console (web/dashboard)
// calls against the admin port. Indexer reads are unauthenticated and are not
// listed here.
//
// Keep this in sync when adding a panel: the tests below are what guarantee the
// console runs on readonly.macaroon and cannot be handed a credential that also
// permits withdrawals, sweeps, note minting or settings changes.
var consoleMethods = map[string][]string{
	arkv1.AdminService_ServiceDesc.ServiceName: {
		"GetScheduledSweep",
		"GetRoundDetails",
		"GetRoundIntents",
		"GetRounds",
		"GetOffchainTxs",
		"GetOffchainTxDetails",
		"GetFeeRate",
		"GetScheduledSessionConfig",
		"ListIntents",
		"GetIntentFees",
		"GetConvictions",
		"GetConvictionsInRange",
		"GetConvictionsByRound",
		"GetActiveScriptConvictions",
		"GetExpiringLiquidity",
		"GetRecoverableLiquidity",
		"GetCollectedFees",
		"GetSettings",
		"GetMainAccountUtxos",
	},
	arkv1.WalletService_ServiceDesc.ServiceName: {
		"GetBalance",
	},
	// WalletInitializerService/GetStatus is whitelisted rather than restricted:
	// it has to answer before anyone holds a credential. The console calls it,
	// but it needs no permission, so it is not listed here.
}

// TestConsoleRunsOnReadOnlyMacaroon asserts the console's whole surface is
// satisfied by ReadOnlyPermissions. If a new panel needs a write op this fails,
// which is the point: the console is read-only by contract, not by convention.
func TestConsoleRunsOnReadOnlyMacaroon(t *testing.T) {
	granted := make(map[bakery.Op]struct{})
	for _, op := range permissions.ReadOnlyPermissions() {
		granted[op] = struct{}{}
	}

	all := permissions.AllPermissionsByMethod()

	for service, methods := range consoleMethods {
		for _, name := range methods {
			method := fmt.Sprintf("/%s/%s", service, name)
			required, ok := all[method]
			require.True(t, ok, "no permission entry for %s", method)
			require.NotEmpty(t, required, "%s has no required ops", method)

			for _, op := range required {
				require.Equal(t, "read", op.Action,
					"%s requires a %q op; the console must only need reads", method, op.Action)
				require.Contains(t, granted, op,
					"%s needs %v, which readonly.macaroon does not grant", method, op)
			}
		}
	}
}

// TestReadOnlyMacaroonCannotWrite is the other half: the credential handed to
// the console must not authorise anything that moves funds or changes state.
func TestReadOnlyMacaroonCannotWrite(t *testing.T) {
	granted := make(map[bakery.Op]struct{})
	for _, op := range permissions.ReadOnlyPermissions() {
		require.Equal(t, "read", op.Action, "ReadOnlyPermissions must not contain a write op")
		granted[op] = struct{}{}
	}

	// A representative sample of the dangerous surface. Each must require at
	// least one op the read-only macaroon does not hold.
	forbidden := []string{
		fmt.Sprintf("/%s/Withdraw", arkv1.WalletService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/Lock", arkv1.WalletService_ServiceDesc.ServiceName),
		// A GET, but it advances the wallet's derivation index, so it is a write
		// and the console deliberately does not call it.
		fmt.Sprintf("/%s/DeriveAddress", arkv1.WalletService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/Sweep", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/CreateNote", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/UpdateSettings", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/BanScript", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/PardonConviction", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/DeleteIntents", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/UpdateIntentFees", arkv1.AdminService_ServiceDesc.ServiceName),
		fmt.Sprintf("/%s/RevokeAuth", arkv1.AdminService_ServiceDesc.ServiceName),
	}

	all := permissions.AllPermissionsByMethod()
	for _, method := range forbidden {
		required, ok := all[method]
		require.True(t, ok, "no permission entry for %s", method)

		satisfied := true
		for _, op := range required {
			if _, held := granted[op]; !held {
				satisfied = false
				break
			}
		}
		require.False(t, satisfied,
			"readonly.macaroon would authorise %s; it must not", method)
	}
}
