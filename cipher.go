// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

var (
	_ Cipher = DES
	_ Cipher = TripleDES
	_ Cipher = AES
)

type Cipher func(key []byte) (cipher.Block, error)

func DES(key []byte) (cipher.Block, error) {
	return des.NewCipher(key)
}

func TripleDES(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

func AES(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
