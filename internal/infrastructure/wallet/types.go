package walletclient

import arkwalletv1 "github.com/arkade-os/api-spec/protobuf/gen/arkwallet/v1"

type txInput struct {
	txId   string
	index  uint32
	script string
	value  uint64
}

func (t txInput) GetTxid() string {
	return t.txId
}

func (t txInput) GetIndex() uint32 {
	return t.index
}

func (t txInput) GetScript() string {
	return t.script
}

func (t txInput) GetValue() uint64 {
	return t.value
}

type walletStatus struct {
	resp *arkwalletv1.StatusResponse
}

func (ws *walletStatus) IsInitialized() bool { return ws.resp.GetInitialized() }
func (ws *walletStatus) IsUnlocked() bool    { return ws.resp.GetUnlocked() }
func (ws *walletStatus) IsSynced() bool      { return ws.resp.GetSynced() }

func (w *walletDaemonClient) Close() {
	_ = w.conn.Close()
}
