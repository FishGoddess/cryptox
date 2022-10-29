// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
)

// Encrypter encrypts data to bytes, hex, and base64.
type Encrypter struct {
	cipher  Cipher
	key     []byte
	mode    EncryptMode
	iv      []byte
	padding Padding
}

// NewEncrypter returns a new encrypter.
func NewEncrypter(cipher Cipher, key []byte, mode EncryptMode, iv []byte, padding Padding) Encrypter {
	return Encrypter{
		cipher:  cipher,
		key:     key,
		mode:    mode,
		iv:      iv,
		padding: padding,
	}
}

// Encrypt encrypts data to bytes.
func (e Encrypter) Encrypt(plain Bytes) (Bytes, error) {
	block, err := e.cipher(e.key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plain = plain.Clone()
	plain = e.padding(plain, blockSize)

	crypted := plain

	err = e.mode.Crypt(block, e.iv, plain, crypted)
	if err != nil {
		return nil, err
	}

	return crypted, nil
}

// EncryptHex encrypts data to string in hex.
func (e Encrypter) EncryptHex(plain Bytes) (string, error) {
	crypted, err := e.Encrypt(plain)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

// EncryptBase64 encrypts data to string in base64.
func (e Encrypter) EncryptBase64(plain Bytes) (string, error) {
	crypted, err := e.Encrypt(plain)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}
