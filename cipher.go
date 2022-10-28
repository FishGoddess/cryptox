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

// Cipher is a function returning a cipher.Block and an error if failed.
type Cipher func(key []byte) (cipher.Block, error)

// DES return a cipher.Block in des and an error if failed.
func DES(key []byte) (cipher.Block, error) {
	return des.NewCipher(key)
}

// TripleDES return a cipher.Block in 3des and an error if failed.
func TripleDES(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(key)
}

// AES return a cipher.Block in aes and an error if failed.
func AES(key []byte) (cipher.Block, error) {
	return aes.NewCipher(key)
}
