// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"reflect"
	"testing"
)

// go test -v -cover -run=^TestMD5$
func TestMD5(t *testing.T) {
	hash := MD5()
	expect := md5.New()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestSHA1$
func TestSHA1(t *testing.T) {
	hash := SHA1()
	expect := sha1.New()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestSHA224$
func TestSHA224(t *testing.T) {
	hash := SHA224()
	expect := sha256.New224()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestSHA256$
func TestSHA256(t *testing.T) {
	hash := SHA256()
	expect := sha256.New()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestSHA384$
func TestSHA384(t *testing.T) {
	hash := SHA384()
	expect := sha512.New384()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestSHA512$
func TestSHA512(t *testing.T) {
	hash := SHA512()
	expect := sha512.New()

	hashType := reflect.TypeOf(hash)
	expectType := reflect.TypeOf(expect)

	if hashType.String() != expectType.String() {
		t.Errorf("hashType.String() %s != expectType.String() %s", hashType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestHasherHash$
func TestHasherHash(t *testing.T) {
	cases := map[string]string{
		"":      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"123":   "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
		"你好，世界": "46932f1e6ea5216e77f58b1908d72ec9322ed129318c6d4bd4450b5eaab9d7e7",
	}

	for input, expect := range cases {
		sum, err := NewHasher(SHA256).Hash([]byte(input))
		if err != nil {
			t.Error(err)
		}

		if sum.Hex() != expect {
			t.Errorf("input %s: sum.Hex() %s != expect %s", input, sum.Hex(), expect)
		}
	}
}
