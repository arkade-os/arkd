package redislivestore

func safeSend(ch chan struct{}) {
	defer func() { recover() }()
	if ch != nil {
		ch <- struct{}{}
	}
}
