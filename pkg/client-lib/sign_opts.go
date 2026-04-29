package arksdk

import "fmt"

// SignOption is the intersection of every option family that accepts signing
// keys. A value that satisfies SignOption can be passed to any method taking
// SendOption, BatchSessionOption, or UnrollOption — so WithKeys is defined
// once here instead of duplicated per family.
type SignOption interface {
	SendOption
	BatchSessionOption
	UnrollOption
}

type keysOpt struct {
	keys map[string]string
}

func (k keysOpt) applySend(o *sendOptions) error {
	if len(o.signingKeys) > 0 {
		return fmt.Errorf("signing keys already set")
	}
	if len(k.keys) == 0 {
		return fmt.Errorf("missing signing keys")
	}
	o.signingKeys = k.keys
	return nil
}

func (k keysOpt) applyBatch(o *batchSessionOptions) error {
	if len(o.keyIdsByScript) > 0 {
		return fmt.Errorf("signing keys already set")
	}
	if len(k.keys) == 0 {
		return fmt.Errorf("missing signing keys")
	}
	o.keyIdsByScript = k.keys
	return nil
}

func (k keysOpt) applyUnroll(o *unrollOptions) error {
	if len(o.signingKeys) > 0 {
		return fmt.Errorf("signing keys already set")
	}
	if len(k.keys) == 0 {
		return fmt.Errorf("missing signing keys")
	}
	o.signingKeys = k.keys
	return nil
}

// WithKeys is usable in SendOffChain, Settle, Unroll, and every other method
// that currently accepts one of the three option families.
func WithKeys(keys map[string]string) SignOption {
	return keysOpt{keys: keys}
}
