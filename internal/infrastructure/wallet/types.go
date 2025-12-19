package walletclient

import arkwalletv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/arkwallet/v1"

type walletStatus struct {
	resp *arkwalletv1.StatusResponse
}

func (ws *walletStatus) IsInitialized() bool { return ws.resp.GetInitialized() }
func (ws *walletStatus) IsUnlocked() bool    { return ws.resp.GetUnlocked() }
func (ws *walletStatus) IsSynced() bool      { return ws.resp.GetSynced() }

func (w *walletDaemonClient) Close() {
	_ = w.conn.Close()
}
