.PHONY: fmt test bench

fmt:
	go fmt ./...

test:
	go test -cover ./...

bench:
	go test -v ./_examples/hash_test.go -bench=. -benchtime=1s
	go test -v ./_examples/des_test.go -bench=. -benchtime=1s
	go test -v ./_examples/triple_des_test.go -bench=. -benchtime=1s
	go test -v ./_examples/aes_test.go -bench=. -benchtime=1s
	go test -v ./_examples/rsa_key_test.go -bench=. -benchtime=1s
	go test -v ./_examples/rsa_test.go -bench=. -benchtime=1s

all: fmt test bench