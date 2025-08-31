package retry

type noopLogger struct{}

func (n *noopLogger) Debug(msg string, keyvals ...any) {}
func (n *noopLogger) Info(msg string, keyvals ...any)  {}
func (n *noopLogger) Warn(msg string, keyvals ...any)  {}
func (n *noopLogger) Error(msg string, keyvals ...any) {}
func (n *noopLogger) With(args ...any) Logger {
	return &noopLogger{}
}
