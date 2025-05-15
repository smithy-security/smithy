//go:build tools

package tools

// Mocks GEN
//go:generate go run go.uber.org/mock/mockgen -package reporter_test -source internal/reporter/reporter.go -destination internal/reporter/reporter_mock_test.go
