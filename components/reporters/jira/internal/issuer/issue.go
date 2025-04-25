package issuer

// Issue carries the data needed to raise issues.
type Issue struct {
	Description string
	Summary     string
	ID          uint64
	Priority    string
}
