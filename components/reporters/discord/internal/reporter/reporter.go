package reporter

type Reporter interface {
	Report(string, ...interface{}) error
}
