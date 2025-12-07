.PHONY: fmt test bench

all: fmt test

fmt:
	go fmt ./...

test:
	go test -v -cover ./...

bench:
	go test -v ./_examples/hash_test.go -bench=. -benchtime=1s
	go test -v ./_examples/hmac_test.go -bench=. -benchtime=1s
	go test -v ./_examples/des_test.go -bench=. -benchtime=1s
	go test -v ./_examples/triple_des_test.go -bench=. -benchtime=1s
	go test -v ./_examples/aes_test.go -bench=. -benchtime=1s
	go test -v ./_examples/rsa_test.go -bench=. -benchtime=1s
	go test -v ./_examples/rsa_key_test.go -bench=. -benchtime=1s
	go test -v ./_examples/ed25519_test.go -bench=. -benchtime=1s
	go test -v ./_examples/ed25519_key_test.go -bench=. -benchtime=1s
