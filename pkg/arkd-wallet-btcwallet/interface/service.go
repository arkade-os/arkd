package interfaces

type Service interface {
	Start() error
	Stop()
}
