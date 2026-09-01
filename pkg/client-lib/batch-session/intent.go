package batchsession

import (
	"context"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
)

// BuildAndSignRegisterIntent builds and signs an intent to be registered for joining a batch
func BuildAndSignRegisterIntent(
	ctx context.Context, args IntentArgs,
) (string, string, extension.Extension, error) {
	if err := args.validateForRegister(); err != nil {
		return "", "", nil, err
	}

	inputs, assetInputs, leafProofs, psbtFields, err := args.intentInputs()
	if err != nil {
		return "", "", nil, err
	}

	message, outputsTxOut, ext, err := registerIntentMessage(
		assetInputs, args.Outputs, args.Cosigners,
	)
	if err != nil {
		return "", "", nil, err
	}

	proof, message, err := buildAndSignIntent(
		ctx, message, inputs, outputsTxOut, leafProofs,
		psbtFields, args.signingRequired(), args.SignTx,
	)
	if err != nil {
		return "", "", nil, err
	}

	return proof, message, ext, nil
}

// BuildAndSignDeleteIntent builds and signs an intent message used to withdraw
// a previously registered intent from the server's pending batch. It does NOT
// submit the request — the caller is responsible for sending it.
func BuildAndSignDeleteIntent(ctx context.Context, args IntentArgs) (string, string, error) {
	if err := args.validateForDelete(); err != nil {
		return "", "", err
	}

	inputs, _, leafProofs, psbtFields, err := args.intentInputs()
	if err != nil {
		return "", "", err
	}

	message, err := intent.DeleteMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeDelete,
		},
		ExpireAt: time.Now().Add(2 * time.Minute).Unix(),
	}.Encode()
	if err != nil {
		return "", "", err
	}

	return buildAndSignIntent(
		ctx, message, inputs, nil, leafProofs, psbtFields, args.signingRequired(), args.SignTx,
	)
}

// BuildAndSignGetPendingTxIntent builds and signs an intent message used to
// fetch a pending offchain transaction for the provided vtxos. It does NOT
// submit the request — the caller is responsible for sending it.
func BuildAndSignGetPendingTxIntent(ctx context.Context, args IntentArgs) (string, string, error) {
	if err := args.validateForGetPendingTx(); err != nil {
		return "", "", err
	}

	inputs, _, leafProofs, psbtFields, err := args.intentInputs()
	if err != nil {
		return "", "", err
	}

	message, err := intent.GetPendingTxMessage{
		BaseMessage: intent.BaseMessage{
			Type: intent.IntentMessageTypeGetPendingTx,
		},
		ExpireAt: time.Now().Add(10 * time.Minute).Unix(), // valid for 10 minutes
	}.Encode()
	if err != nil {
		return "", "", err
	}

	return buildAndSignIntent(
		ctx, message, inputs, nil, leafProofs, psbtFields, args.signingRequired(), args.SignTx,
	)
}
