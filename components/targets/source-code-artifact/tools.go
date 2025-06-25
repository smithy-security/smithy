//go:build tools

package tools

// Mocks GEN
//go:generate go run go.uber.org/mock/mockgen -package target_test -source internal/target/target.go -destination internal/target/target_mock_test.go Fetcher,Extractor,Persister,MetadataWriter
//go:generate go run go.uber.org/mock/mockgen -package remote_test -source internal/artifact/fetcher/remote/fetcher.go -destination internal/artifact/fetcher/remote/fetcher_mock_test.go Doer
