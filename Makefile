.PHONY: fmt test bench

fmt:
	go fmt ./...

test:
	go test -cover ./...

bench:
	go test -v ./_examples/performance_test.go -bench=. -benchtime=1s

all: fmt test bench