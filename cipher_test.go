// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/aes"
	"crypto/des"
	"reflect"
	"testing"
)

// go test -v -cover -run=^TestDES$
func TestDES(t *testing.T) {
	testKey := []byte("12345678")

	block, err := DES(testKey)
	if err != nil {
		t.Error(err)
	}

	expect, err := des.NewCipher(testKey)
	if err != nil {
		t.Error(err)
	}

	blockType := reflect.TypeOf(block)
	expectType := reflect.TypeOf(expect)

	if blockType.String() != expectType.String() {
		t.Errorf("blockType.String() %s != expectType.String() %s", blockType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestTripleDES$
func TestTripleDES(t *testing.T) {
	testKey := []byte("123456788765432112345678")

	block, err := TripleDES(testKey)
	if err != nil {
		t.Error(err)
	}

	expect, err := des.NewTripleDESCipher(testKey)
	if err != nil {
		t.Error(err)
	}

	blockType := reflect.TypeOf(block)
	expectType := reflect.TypeOf(expect)

	if blockType.String() != expectType.String() {
		t.Errorf("blockType.String() %s != expectType.String() %s", blockType.String(), expectType.String())
	}
}

// go test -v -cover -run=^TestAES$
func TestAES(t *testing.T) {
	testKey := []byte("12345678876543211234567887654321")

	block, err := AES(testKey)
	if err != nil {
		t.Error(err)
	}

	expect, err := aes.NewCipher(testKey)
	if err != nil {
		t.Error(err)
	}

	blockType := reflect.TypeOf(block)
	expectType := reflect.TypeOf(expect)

	if blockType.String() != expectType.String() {
		t.Errorf("blockType.String() %s != expectType.String() %s", blockType.String(), expectType.String())
	}
}
