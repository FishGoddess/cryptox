// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"slices"
	"testing"

	"github.com/FishGoddess/cryptox/bytes/encoding"
)

// go test -v -cover -run=^TestSHA1$
func TestSHA1(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
		"123":   []byte("40bd001563085fc35165329ea1ff5c5ecbdbbeef"),
		"你好，世界": []byte("3becb03b015ed48050611c8d7afe4b88f70d5a20"),
	}

	for data, expect := range testCases {
		got := SHA1([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := sha1.New()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestSHA224$
func TestSHA224(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"),
		"123":   []byte("78d8045d684abd2eece923758f3cd781489df3a48e1278982466017f"),
		"你好，世界": []byte("9a65a12818b8e6ac357cee9337565337f55bda8a45b0c1bfb9f4403c"),
	}

	for data, expect := range testCases {
		got := SHA224([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := sha256.New224()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestSHA256$
func TestSHA256(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
		"123":   []byte("a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"),
		"你好，世界": []byte("46932f1e6ea5216e77f58b1908d72ec9322ed129318c6d4bd4450b5eaab9d7e7"),
	}

	for data, expect := range testCases {
		got := SHA256([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := sha256.New()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestSHA384$
func TestSHA384(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
		"123":   []byte("9a0a82f0c0cf31470d7affede3406cc9aa8410671520b727044eda15b4c25532a9b5cd8aaf9cec4919d76255b6bfb00f"),
		"你好，世界": []byte("fbea16d8be2993f2cda1ef9fc055f53f0fa23f1e1dc4a57a7548c36227c3ef0491484fcf1e30c5d1ff17441a5ce89a11"),
	}

	for data, expect := range testCases {
		got := SHA384([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := sha512.New384()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}

// go test -v -cover -run=^TestSHA512$
func TestSHA512(t *testing.T) {
	testCases := map[string][]byte{
		"":      []byte("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"),
		"123":   []byte("3c9909afec25354d551dae21590bb26e38d53f2173b8d3dc3eee4c047e7ab1c1eb8b85103e3be7ba613b31bb5c9c36214dc9f14a42fd7a2fdb84856bca5c44c2"),
		"你好，世界": []byte("45a6e3fe78af4a3326da9bf8c3407bca5fef80b334c046d20544b0b28be6c761718cfaf5b752eaa89849b83a4d4e5f6df4908e195cd8c159181e78971910db13"),
	}

	for data, expect := range testCases {
		got := SHA512([]byte(data), encoding.Hex)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}

		h := sha512.New()
		h.Write([]byte(data))

		expect = h.Sum(nil)
		expect = encoding.Hex.Encode(expect)
		if !slices.Equal(got, expect) {
			t.Fatalf("data %s: got %s != expect %s", data, got, expect)
		}
	}
}
