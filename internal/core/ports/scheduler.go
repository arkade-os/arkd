package ports

type TimeUnit int

const (
	UnixTime TimeUnit = iota
	BlockHeight
)

type SchedulerService interface {
	Start()
	Stop()

	Unit() TimeUnit
	AddNow(expiry int64) int64
	AfterNow(expiry int64) bool
	ScheduleTaskOnce(at int64, task func()) error
}
