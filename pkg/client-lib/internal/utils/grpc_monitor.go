package utils

import (
	"context"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
)

func MonitorGrpcConn(
	ctx context.Context, conn *grpc.ClientConn, onReconnect func(ctx context.Context) error,
) {
	firstReadySeen := false
	wasDisconnected := false

	for {
		select {
		case <-ctx.Done():
			return
		default:
			currentState := conn.GetState()

			if conn.WaitForStateChange(ctx, currentState) {
				newState := conn.GetState()

				// Track if we've seen the initial Ready state
				if newState == connectivity.Ready && !firstReadySeen {
					firstReadySeen = true
					wasDisconnected = false
					continue
				}

				// Mark as disconnected when we hit a failure state
				if !wasDisconnected && newState == connectivity.TransientFailure ||
					newState == connectivity.Shutdown {
					wasDisconnected = true
					if err := onReconnect(ctx); err != nil {
						logrus.WithError(err).Error("failed to reconnect to grpc server")
					}
				}

				// Only trigger callback if we're recovering from a disconnection
				if newState == connectivity.Ready && wasDisconnected {
					wasDisconnected = false
				}
			}
		}
	}
}
