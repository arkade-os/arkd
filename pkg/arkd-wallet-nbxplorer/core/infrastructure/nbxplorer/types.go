package nbxplorer

type bitcoinStatusResponse struct {
	BitcoinStatus struct {
		Blocks               uint32  `json:"blocks"`
		Headers              uint32  `json:"headers"`
		VerificationProgress float64 `json:"verificationProgress"`
		IsSynched            bool    `json:"isSynched"`
		IncrementalRelayFee  float64 `json:"incrementalRelayFee"`
		MinRelayTxFee        float64 `json:"minRelayTxFee"`
		Capabilities         struct {
			CanScanTxoutSet            bool `json:"canScanTxoutSet"`
			CanSupportSegwit           bool `json:"canSupportSegwit"`
			CanSupportTaproot          bool `json:"canSupportTaproot"`
			CanSupportTransactionCheck bool `json:"canSupportTransactionCheck"`
		} `json:"capabilities"`
	} `json:"bitcoinStatus"`
	IsFullySynched bool   `json:"isFullySynched"`
	SyncHeight     uint32 `json:"syncHeight"`
	NetworkType    string `json:"networkType"`
	CryptoCode     string `json:"cryptoCode"`
	InstanceName   string `json:"instanceName,omitempty"`
	Version        string `json:"version"`
}

type transactionResponse struct {
	BlockHash     string `json:"blockHash,omitempty"`
	Confirmations uint32 `json:"confirmations"`
	Height        uint32 `json:"height,omitempty"`
	TransactionId string `json:"transactionId"`
	Transaction   string `json:"transaction,omitempty"`
	Timestamp     int64  `json:"timestamp"`
	ReplacedBy    string `json:"replacedBy,omitempty"`
	Metadata      *struct {
		Vsize   uint32  `json:"vsize,omitempty"`
		Fees    uint64  `json:"fees,omitempty"`
		FeeRate float64 `json:"feeRate,omitempty"`
	} `json:"metadata,omitempty"`
}

type utxoResponse struct {
	Feature         string `json:"feature"`
	Outpoint        string `json:"outpoint"`
	Index           uint32 `json:"index"`
	TransactionHash string `json:"transactionHash"`
	ScriptPubKey    string `json:"scriptPubKey"`
	Address         string `json:"address"`
	Value           uint64 `json:"value"`
	KeyPath         string `json:"keyPath,omitempty"`
	KeyIndex        string `json:"keyIndex,omitempty"`
	Timestamp       int64  `json:"timestamp"`
	Confirmations   uint32 `json:"confirmations"`
}

type balanceResponse struct {
	Unconfirmed uint64 `json:"unconfirmed"`
	Confirmed   uint64 `json:"confirmed"`
	Available   uint64 `json:"available"`
	Immature    uint64 `json:"immature"`
	Total       uint64 `json:"total"`
}

type scriptPubKeyResponse struct {
	TrackedSource      string `json:"trackedSource,omitempty"`
	Feature            string `json:"feature"`
	DerivationStrategy string `json:"derivationStrategy"`
	KeyPath            string `json:"keyPath,omitempty"`
	Index              uint32 `json:"index,omitempty"`
	ScriptPubKey       string `json:"scriptPubKey"`
	Address            string `json:"address"`
	Redeem             string `json:"redeem,omitempty"`
	BlindingKey        string `json:"blindingKey,omitempty"`
}

type addressResponse struct {
	TrackedSource      string `json:"trackedSource,omitempty"`
	Feature            string `json:"feature"`
	DerivationStrategy string `json:"derivationStrategy"`
	KeyPath            string `json:"keyPath,omitempty"`
	Index              uint32 `json:"index,omitempty"`
	ScriptPubKey       string `json:"scriptPubKey"`
	Address            string `json:"address"`
	Redeem             string `json:"redeem,omitempty"`
	BlindingKey        string `json:"blindingKey,omitempty"`
}

type feeRateResponse struct {
	FeeRate    float64 `json:"feeRate"`
	BlockCount uint32  `json:"blockCount"`
}

type broadcastResponse struct {
	TransactionId string `json:"transactionId"`
}

type scanProgressResponse struct {
	Error    string `json:"error,omitempty"`
	QueuedAt int64  `json:"queuedAt"`
	Status   string `json:"status"`
	Progress *struct {
		StartedAt            int64  `json:"startedAt"`
		CompletedAt          int64  `json:"completedAt,omitempty"`
		Found                uint32 `json:"found"`
		BatchNumber          uint32 `json:"batchNumber"`
		RemainingBatches     uint32 `json:"remainingBatches"`
		CurrentBatchProgress uint32 `json:"currentBatchProgress"`
		RemainingSeconds     uint32 `json:"remainingSeconds"`
		OverallProgress      uint32 `json:"overallProgress"`
		From                 uint32 `json:"from"`
		Count                uint32 `json:"count"`
		TotalSearched        uint32 `json:"totalSearched"`
		TotalSizeOfUTXOSet   uint32 `json:"totalSizeOfUTXOSet,omitempty"`
		HighestKeyIndexFound *struct {
			Change  uint32 `json:"change,omitempty"`
			Deposit uint32 `json:"deposit,omitempty"`
			Direct  uint32 `json:"direct,omitempty"`
		} `json:"highestKeyIndexFound"`
	} `json:"progress,omitempty"`
}

// submitPackageResult represents the result of a submitpackage RPC call
type submitPackageResult struct {
	TxResults []submitPackageTxResult `json:"tx_results"`
}

// submitPackageTxResult represents a single transaction result from submitpackage
type submitPackageTxResult struct {
	TxID   string `json:"txid"`
	Result string `json:"result"`
}

// rpcResponse represents a generic JSON-RPC response
type rpcResponse struct {
	Result interface{} `json:"result"`
	Error  *rpcError   `json:"error,omitempty"`
	ID     interface{} `json:"id,omitempty"`
}

// rpcError represents an error in a JSON-RPC response
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Event represents a WebSocket event from NBXplorer
type Event struct {
	EventID int         `json:"eventId"`
	Type    string      `json:"type"`
	Data    interface{} `json:"data"`
}

// NewTransactionEvent represents a new transaction event
type NewTransactionEvent struct {
	BlockID            string `json:"blockId,omitempty"`
	TrackedSource      string `json:"trackedSource"`
	DerivationStrategy string `json:"derivationStrategy"`
	CryptoCode         string `json:"cryptoCode"`
	TransactionData    struct {
		TransactionHash string `json:"transactionHash"`
		Confirmations   int    `json:"confirmations"`
		Height          *int   `json:"height,omitempty"`
		Timestamp       int64  `json:"timestamp"`
	} `json:"transactionData"`
}
