all:
	go build -o ./cmd/regparser ./cmd

generate:
	binparsegen ./conversion.spec.yaml > regparser_gen.go
	gofmt -w regparser_gen.go
