package errors

import (
	"encoding/json"
	"fmt"

	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	log "github.com/sirupsen/logrus"
	grpccodes "google.golang.org/grpc/codes"
)

// Code is the type representing a namespace error code.
type Code[MT any] struct {
	Code     uint16
	Name     string
	GrpcCode grpccodes.Code
}

// New creates a new error with the given code and the message
func (c Code[MT]) New(msg string, args ...any) TypedError[MT] {
	return &ErrorImpl[MT]{
		code:  c,
		cause: fmt.Errorf(msg, args...),
	}
}

// Wrap creates a new Error with the given code and the cause error
func (c Code[MT]) Wrap(cause error) TypedError[MT] {
	return &ErrorImpl[MT]{
		code:  c,
		cause: cause,
	}
}

func (c Code[MT]) String() string {
	return fmt.Sprintf("%s (%d)", c.Name, c.Code)
}

type Error interface {
	error
	Log() *log.Entry
	Code() uint16
	CodeName() string
	GrpcCode() grpccodes.Code
	Metadata() map[string]string
}

type TypedError[MT any] interface {
	Error
	WithMetadata(MT) TypedError[MT]
}

// ErrorImpl is the default concrete implementation of TypedError.
type ErrorImpl[MT any] struct {
	code     Code[MT]
	cause    error
	metadata MT
}

func (e *ErrorImpl[MT]) Log() *log.Entry {
	return log.WithField("name", e.code.Name).
		WithField("code", e.code.Code).
		WithField("metadata", e.metadata)
}

func (e *ErrorImpl[MT]) Metadata() map[string]string {
	// convert any metadata to map[string]string
	metadata := make(map[string]string)
	buf, err := json.Marshal(e.metadata)
	if err == nil {
		var genericMap map[string]any
		if err := json.Unmarshal(buf, &genericMap); err == nil {
			for k, v := range genericMap {
				vStr := ""
				if v != nil {
					vStr = fmt.Sprintf("%v", v)
				}
				metadata[k] = vStr
			}
		}
	}
	return metadata
}

func (e *ErrorImpl[MT]) GrpcCode() grpccodes.Code {
	return e.code.GrpcCode
}

func (e *ErrorImpl[MT]) Code() uint16 {
	return e.code.Code
}

func (e *ErrorImpl[MT]) CodeName() string {
	return e.code.Name
}

// Error() implements the error interface.
func (e *ErrorImpl[MT]) Error() string {
	return fmt.Sprintf("%s: %s", e.code.String(), e.cause.Error())
}

func (e *ErrorImpl[MT]) WithMetadata(metadata MT) TypedError[MT] {
	e.metadata = metadata
	return e
}

type VtxoMetadata struct {
	VtxoOutpoint string `json:"vtxo_outpoint"`
}

type PsbtMetadata struct {
	Tx string `json:"tx"`
}

type PsbtInputMetadata struct {
	Txid string `json:"txid"`
}

type InputMetadata struct {
	Txid       string `json:"txid"`
	InputIndex int    `json:"input_index"`
}

type InvalidVtxoScriptMetadata struct {
	Tapscripts []string `json:"tapscripts"`
}

type ForfeitClosureLockedMetadata struct {
	Locktime        int    `json:"locktime"`
	CurrentLocktime int    `json:"current_locktime"`
	Type            string `json:"type"`
}

type AmountTooHighMetadata struct {
	OutputIndex int `json:"output_index"`
	Amount      int `json:"amount"`
	MaxAmount   int `json:"max_amount"`
}

type AmountTooLowMetadata struct {
	OutputIndex int `json:"output_index"`
	Amount      int `json:"amount"`
	MinAmount   int `json:"min_amount"`
}

type CheckpointMismatchMetadata struct {
	ExpectedTxid string `json:"expected_txid"`
}

type ArkTxMismatchMetadata struct {
	ExpectedTxid string `json:"expected_txid"`
	GotTxid      string `json:"got_txid"`
}

type InvalidSignatureMetadata struct {
	Tx string `json:"tx"`
}

type TxNotFoundMetadata struct {
	Txid string `json:"txid"`
}

type IntentTimeRangeMetadata struct {
	ValidAt  int64 `json:"valid_at"`
	ExpireAt int64 `json:"expire_at"`
	Now      int64 `json:"now"`
}

type InvalidIntentMessageMetadata struct {
	Message intent.BaseMessage `json:"message"`
}

type InvalidIntentProofMetadata struct {
	Proof   string `json:"proof"`
	Message string `json:"message"`
}

type InvalidPkScriptMetadata struct {
	Script string `json:"script"`
}

type InvalidForfeitTxsMetadata struct {
	ForfeitTxs []string `json:"forfeit_txs"`
}

type InvalidBoardingInputSigMetadata struct {
	SignedCommitmentTx string `json:"signed_commitment_tx"`
}

type VtxoNotFoundMetadata struct {
	VtxoOutpoints []string `json:"vtxo_outpoints"`
	GotVtxos      []string `json:"got_vtxos"`
}

type IntentInsufficientFeeMetadata struct {
	InputExpectedFees  map[string]int `json:"input_expected_fees"`
	OutputExpectedFees map[string]int `json:"output_expected_fees"`
	ExpectedFee        int            `json:"expected_fee"`
	ActualFee          int            `json:"actual_fee"`
}

type OffchainTxInsufficientFeeMetadata struct {
	ExpectedFee         int            `json:"expected_fee"`
	ActualFee           int            `json:"actual_fee"`
	InputThrottledUntil map[string]any `json:"input_throttled_until"`
}

var INTERNAL_ERROR = Code[map[string]any]{0, "INTERNAL_ERROR", grpccodes.Internal}
var INVALID_ARK_PSBT = Code[PsbtMetadata]{1, "INVALID_ARK_PSBT", grpccodes.InvalidArgument}

var INVALID_CHECKPOINT_PSBT = Code[PsbtMetadata]{
	2,
	"INVALID_CHECKPOINT_PSBT",
	grpccodes.InvalidArgument,
}

var INVALID_PSBT_MISSING_INPUT = Code[PsbtInputMetadata]{
	3,
	"INVALID_PSBT_MISSING_INPUT",
	grpccodes.InvalidArgument,
}

var VTXO_ALREADY_REGISTERED = Code[VtxoMetadata]{
	4,
	"VTXO_ALREADY_REGISTERED",
	grpccodes.AlreadyExists,
}

var INVALID_PSBT_INPUT = Code[InputMetadata]{
	5,
	"INVALID_PSBT_INPUT",
	grpccodes.InvalidArgument,
}
var VTXO_ALREADY_SPENT = Code[VtxoMetadata]{6, "VTXO_ALREADY_SPENT", grpccodes.InvalidArgument}
var VTXO_ALREADY_UNROLLED = Code[VtxoMetadata]{7, "VTXO_ALREADY_UNROLLED", grpccodes.InvalidArgument}
var VTXO_RECOVERABLE = Code[VtxoMetadata]{8, "VTXO_RECOVERABLE", grpccodes.InvalidArgument}

var OFFCHAIN_TX_SPENDING_NOTE = Code[VtxoMetadata]{
	9,
	"OFFCHAIN_TX_SPENDING_NOTE",
	grpccodes.InvalidArgument,
}

var INVALID_VTXO_SCRIPT = Code[InvalidVtxoScriptMetadata]{
	10,
	"INVALID_VTXO_SCRIPT",
	grpccodes.InvalidArgument,
}

var FORFEIT_CLOSURE_LOCKED = Code[ForfeitClosureLockedMetadata]{
	11,
	"FORFEIT_CLOSURE_LOCKED",
	grpccodes.FailedPrecondition,
}

var ARK_TX_INPUT_NOT_SIGNED = Code[InputMetadata]{
	12,
	"ARK_TX_INPUT_NOT_SIGNED",
	grpccodes.InvalidArgument,
}
var MALFORMED_ARK_TX = Code[PsbtMetadata]{13, "MALFORMED_ARK_TX", grpccodes.InvalidArgument}
var AMOUNT_TOO_HIGH = Code[AmountTooHighMetadata]{14, "AMOUNT_TOO_HIGH", grpccodes.InvalidArgument}
var AMOUNT_TOO_LOW = Code[AmountTooLowMetadata]{15, "AMOUNT_TOO_LOW", grpccodes.InvalidArgument}

var CHECKPOINT_MISMATCH = Code[CheckpointMismatchMetadata]{
	16,
	"CHECKPOINT_MISMATCH",
	grpccodes.InvalidArgument,
}
var ARK_TX_MISMATCH = Code[ArkTxMismatchMetadata]{17, "ARK_TX_MISMATCH", grpccodes.InvalidArgument}

var INVALID_SIGNATURE = Code[InvalidSignatureMetadata]{
	18,
	"INVALID_SIGNATURE",
	grpccodes.InvalidArgument,
}
var TX_NOT_FOUND = Code[TxNotFoundMetadata]{19, "TX_NOT_FOUND", grpccodes.NotFound}

var INVALID_INTENT_TIMERANGE = Code[IntentTimeRangeMetadata]{
	20,
	"INVALID_INTENT_TIMERANGE",
	grpccodes.InvalidArgument,
}

var INVALID_INTENT_MESSAGE = Code[InvalidIntentMessageMetadata]{
	21,
	"INVALID_INTENT_MESSAGE",
	grpccodes.InvalidArgument,
}
var INVALID_INTENT_PSBT = Code[PsbtMetadata]{22, "INVALID_INTENT_PSBT", grpccodes.InvalidArgument}

var INVALID_INTENT_PROOF = Code[InvalidIntentProofMetadata]{
	23,
	"INVALID_INTENT_PROOF",
	grpccodes.InvalidArgument,
}

var INVALID_PKSCRIPT = Code[InvalidPkScriptMetadata]{
	24,
	"INVALID_PKSCRIPT",
	grpccodes.InvalidArgument,
}

var CONFIRMATION_SESSION_NOT_STARTED = Code[any]{
	25,
	"CONFIRMATION_SESSION_NOT_STARTED",
	grpccodes.InvalidArgument,
}

var INVALID_FORFEIT_TXS = Code[InvalidForfeitTxsMetadata]{
	26,
	"INVALID_FORFEIT_TXS",
	grpccodes.InvalidArgument,
}

var INVALID_BOARDING_INPUT_SIG = Code[InvalidBoardingInputSigMetadata]{
	27,
	"INVALID_BOARDING_INPUT_SIG",
	grpccodes.InvalidArgument,
}
var SIGNING_SESSION_TIMED_OUT = Code[any]{28, "SIGNING_SESSION_TIMED_OUT", grpccodes.Internal}
var VTXO_BANNED = Code[VtxoMetadata]{29, "VTXO_BANNED", grpccodes.InvalidArgument}
var VTXO_NOT_FOUND = Code[VtxoNotFoundMetadata]{30, "VTXO_NOT_FOUND", grpccodes.NotFound}

var INTENT_INSUFFICIENT_FEE = Code[IntentInsufficientFeeMetadata]{
	31,
	"INTENT_INSUFFICIENT_FEE",
	grpccodes.InvalidArgument,
}

var OFFCHAIN_TX_INSUFFICIENT_FEE = Code[OffchainTxInsufficientFeeMetadata]{
	32,
	"OFFCHAIN_TX_INSUFFICIENT_FEE",
	grpccodes.InvalidArgument,
}

var ASSET_VALIDATION_FAILED = Code[map[string]any]{
	33,
	"ASSET_VALIDATION_FAILED",
	grpccodes.InvalidArgument,
}
