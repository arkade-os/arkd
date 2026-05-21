package batchsessionhandler

type HandlerOption func(*options)

func WithSkipVtxoTreeSigning() HandlerOption {
	return func(o *options) {
		o.signVtxoTree = false
	}
}

func WithReplay(ch chan<- any) HandlerOption {
	return func(o *options) {
		o.replayEventsCh = ch
	}
}

func WithCancel(cancelCh <-chan struct{}) HandlerOption {
	return func(o *options) {
		o.cancelCh = cancelCh
	}
}

type options struct {
	signVtxoTree   bool              // default: true
	replayEventsCh chan<- any        // default: nil
	cancelCh       <-chan struct{}   // default: nil
	keysByScript   map[string]string // default: nil
}

func newOptions() *options {
	return &options{signVtxoTree: true}
}
