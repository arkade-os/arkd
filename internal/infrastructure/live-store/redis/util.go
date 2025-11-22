package redislivestore

import log "github.com/sirupsen/logrus"

func safeSend(ch chan struct{}) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("safeSend recovered from panic: %v", r)
		}
	}()

	if ch != nil {
		ch <- struct{}{}
	}
}
