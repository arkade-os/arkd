package interceptors

// func unaryPanicRecoveryInterceptor() grpc.UnaryServerInterceptor {
// 	return func(
// 		ctx context.Context, req interface{},
// 		info *grpc.UnaryServerInfo, handler grpc.UnaryHandler,
// 	) (interface{}, error) {
// 		defer func() {
// 			if r := recover(); r != nil {
// 				log.Errorf("panic-recovery middleware recovered from panic: %v", r)
// 				log.Tracef(
// 					"panic-recovery middleware recovered from panic: %v", string(debug.Stack()),
// 				)
// 			}
// 		}()

// 		return handler(ctx, req)
// 	}
// }

// func streamPanicRecoveryInterceptor() grpc.StreamServerInterceptor {
// 	return func(
// 		srv interface{}, stream grpc.ServerStream,
// 		info *grpc.StreamServerInfo, handler grpc.StreamHandler,
// 	) error {
// 		defer func() {
// 			if r := recover(); r != nil {
// 				log.Errorf("panic-recovery middleware recovered from panic: %v", r)
// 				log.Tracef(
// 					"panic-recovery middleware recovered from panic: %v", string(debug.Stack()),
// 				)
// 			}
// 		}()

// 		return handler(srv, stream)
// 	}
// }
