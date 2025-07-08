package permissions

import (
	"fmt"

	arkv1 "github.com/arkade-os/api-spec/protobuf/gen/ark/v1"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
)

const (
	EntityWallet  = "wallet"
	EntityAdmin   = "admin"
	EntityManager = "manager"
	EntityArk     = "ark"
	EntityIndexer = "indexer"
	EntityHealth  = "health"
)

// ReadOnlyPermissions returns the permissions of the macaroon readonly.macaroon.
// This grants access to the read action for all entities.
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

// WalletPermissions returns the permissions of the macaroon wallet.macaroon.
// This grants access to the all actions for the wallet entity.
func WalletPermissions() []bakery.Op {
	return []bakery.Op{
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

// ManagerPermissions returns the permissions of the macaroon manager.macaroon.
// This grants access to the all actions for the manager entity.
func ManagerPermissions() []bakery.Op {
	return []bakery.Op{
		{
			Entity: EntityManager,
			Action: "read",
		},
		{
			Entity: EntityManager,
			Action: "write",
		},
	}
}

// AdminPermissions returns the permissions of the macaroon admin.macaroon.
// This grants access to the all actions for all entities.
func AdminPermissions() []bakery.Op {
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

// Whitelist returns the list of all whitelisted methods with the relative
// entity and action.
func Whitelist() map[string][]bakery.Op {
	return map[string][]bakery.Op{
		fmt.Sprintf("/%s/GenSeed", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "read",
		}},
		fmt.Sprintf("/%s/Create", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "write",
		}},
		fmt.Sprintf("/%s/Restore", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "write",
		}},
		fmt.Sprintf("/%s/Unlock", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetStatus", arkv1.WalletInitializerService_ServiceDesc.ServiceName): {{
			Entity: EntityWallet,
			Action: "read",
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
		fmt.Sprintf("/%s/GetInfo", arkv1.ArkService_ServiceDesc.ServiceName): {{
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
			Entity: EntityWallet,
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
			Entity: EntityWallet,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetScheduledSweep", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
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
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/GetMarketHourConfig", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
		fmt.Sprintf("/%s/UpdateMarketHourConfig", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/DeleteIntents", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "write",
		}},
		fmt.Sprintf("/%s/ListIntents", arkv1.AdminService_ServiceDesc.ServiceName): {{
			Entity: EntityManager,
			Action: "read",
		}},
	}
}
