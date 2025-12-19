package permissions

import (
	"fmt"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	EntityWallet            = "wallet"
	EntityWalletInitializer = "walletinitializer"
	EntityManager           = "manager"
	EntityWithdraw          = "withdraw"
	EntityNote              = "note"
	EntityArk               = "ark"
	EntityIndexer           = "indexer"
	EntityHealth            = "health"
	EntityAuthManager       = "authmanager"
)

func ReadOnlyPermissions() []bakery.Op {
	return []bakery.Op{
		{
			Entity: EntityWallet,
			Action: "read",
		},
		{
			Entity: EntityManager,
			Action: "read",
		},
	}
}

func UnlockerPermissions() []bakery.Op {
	return []bakery.Op{
		{
			Entity: EntityWalletInitializer,
			Action: "write",
		},
		{
			Entity: EntityWalletInitializer,
			Action: "read",
		},
		{
			Entity: EntityWallet,
			Action: "read",
		},
		{
			Entity: EntityWallet,
			Action: "write",
		},
	}
}

func OperatorPermissions() []bakery.Op {
	return []bakery.Op{
		{
			Entity: EntityManager,
			Action: "read",
		},
		{
			Entity: EntityManager,
			Action: "write",
		},
		{
			Entity: EntityWallet,
			Action: "read",
		},
		{
			Entity: EntityWallet,
			Action: "write",
		},
	}
}

func AdminPermissions() []bakery.Op {
	seen := make(map[bakery.Op]struct{})
	permissions := make([]bakery.Op, 0)
	for _, op := range append(UnlockerPermissions(), OperatorPermissions()...) {
		if _, ok := seen[op]; ok {
			continue
		}
		seen[op] = struct{}{}
		permissions = append(permissions, op)
	}
	noteWrite := bakery.Op{
		Entity: EntityNote,
		Action: "write",
	}
	if _, ok := seen[noteWrite]; !ok {
		permissions = append(permissions, noteWrite)
	}
	return permissions
}

func SuperUserPermissions() []bakery.Op {
	return append(AdminPermissions(), []bakery.Op{
		{
			Entity: EntityWithdraw,
			Action: "write",
		},
		{
			Entity: EntityAuthManager,
			Action: "write",
		},
	}...)
}

// Whitelist returns the list of all whitelisted methods with the relative
// entity and action.
func Whitelist() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		fmt.Sprintf("/%s/GenSeed", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "read",
		}},
		fmt.Sprintf("/%s/Create", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWalletInitializer,
			Action: "write",
		}},
		fmt.Sprintf("/%s/Restore", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWalletInitializer,
			Action: "write",
		}},
		fmt.Sprintf("/%s/Unlock", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWalletInitializer,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetStatus", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "read",
		}},
		fmt.Sprintf("/%s/LoadSigner", arkv1.SignerManagerService_ServiceDesc.ServiceName): {{
			Entity: EntityWalletInitializer,
			Action: "write",
		}},
		fmt.Sprintf("/%s/RegisterIntent", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/DeleteIntent", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/ConfirmRegistration", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/SubmitSignedForfeitTxs", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetEventStream", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "read",
		}},
		fmt.Sprintf("/%s/UpdateStreamTopics", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetInfo", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "read",
		}},
		fmt.Sprintf("/%s/EstimateIntentFee", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "read",
		}},
		fmt.Sprintf("/%s/SubmitTx", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/FinalizeTx", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetPendingTx", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "read",
		}},
		fmt.Sprintf("/%s/Check", grpchealth.Health_ServiceDesc.ServiceName): {{
			Entity: EntityHealth,
			Action: "read",
		}},
		fmt.Sprintf("/%s/SubmitTreeNonces", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/SubmitTreeSignatures", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetTransactionsStream", arkv1.ArkService_ServiceDesc.ServiceName): {{
			Entity: EntityArk,
			Action: "read",
		}},
		/* Indexer APIs */
		fmt.Sprintf("/%s/GetCommitmentTx", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetForfeitTxs", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetConnectors", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetVtxoTree", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetVtxoTreeLeaves", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetVtxos", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetTransactionHistory", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetVtxoChain", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetVirtualTxs", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetBatchSweepTransactions", arkv1.IndexerService_ServiceDesc.ServiceName): {
			{
				Entity: EntityIndexer,
				Action: "read",
			},
		},
		fmt.Sprintf("/%s/SubscribeForScripts", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/UnsubscribeForScripts", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetSubscription", arkv1.IndexerService_ServiceDesc.ServiceName): {{
			Entity: EntityIndexer,
			Action: "read",
		}},
	}
}

// AllPermissionsByMethod returns a mapping of the RPC server calls to the
// permissions they require.
func AllPermissionsByMethod() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		fmt.Sprintf("/%s/Lock", arkv1.WalletService_ServiceDesc.ServiceName): {{
			Entity: EntityWalletInitializer,
			Action: "write",
		}},
		fmt.Sprintf("/%s/DeriveAddress", arkv1.WalletService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetBalance", arkv1.WalletService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "read",
		}},
		fmt.Sprintf("/%s/Withdraw", arkv1.WalletService_ServiceDesc.ServiceName): {{
			Entity: EntityWithdraw,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetScheduledSweep", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/Sweep", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetRoundDetails", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetRounds", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/CreateNote", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityNote,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetScheduledSessionConfig", arkv1.AdminService_ServiceDesc.ServiceName): {
			{
				Entity: EntityManager,
				Action: "read",
			},
		},
		fmt.Sprintf("/%s/UpdateScheduledSessionConfig", arkv1.AdminService_ServiceDesc.ServiceName): {
			{
				Entity: EntityManager,
				Action: "write",
			},
		},
		fmt.Sprintf("/%s/ClearScheduledSessionConfig", arkv1.AdminService_ServiceDesc.ServiceName): {
			{
				Entity: EntityManager,
				Action: "write",
			},
		},
		fmt.Sprintf("/%s/DeleteIntents", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/ListIntents", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		// Conviction management RPCs
		fmt.Sprintf("/%s/GetConvictions", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetConvictionsInRange", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetConvictionsByRound", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/GetActiveScriptConvictions", arkv1.AdminService_ServiceDesc.ServiceName): {
			{
				Entity: EntityManager,
				Action: "read",
			},
		},
		fmt.Sprintf("/%s/PardonConviction", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/BanScript", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/RevokeAuth", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityAuthManager,
			Action: "write",
		}},
	}
}
