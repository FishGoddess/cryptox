// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
)

type Encrypter interface {
	Encrypt(plain []byte) ([]byte, error)
	EncryptHex(plain []byte) (string, error)
	EncryptBase64(plain []byte) (string, error)
}

type encrypter struct {
	cipher  Cipher
	key     []byte
	mode    EncryptMode
	iv      []byte
	padding Padding
}

func NewEncrypter(cipher Cipher, key []byte, mode EncryptMode, iv []byte, padding Padding) Encrypter {
	return encrypter{
		cipher:  cipher,
		key:     key,
		mode:    mode,
		iv:      iv,
		padding: padding,
	}
}

func (e encrypter) Encrypt(plain []byte) ([]byte, error) {
	block, err := e.cipher(e.key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plain = copyBytes(plain)
	plain = e.padding(plain, blockSize)

	crypted := plain

	err = e.mode.Crypt(block, e.iv, plain, crypted)
	if err != nil {
		return nil, err
	}

	return crypted, nil
}

func (e encrypter) EncryptHex(plain []byte) (string, error) {
	crypted, err := e.Encrypt(plain)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (e encrypter) EncryptBase64(plain []byte) (string, error) {
	crypted, err := e.Encrypt(plain)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}
