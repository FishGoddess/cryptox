// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/pkg/bytes"
)

type Encryptor struct {
	cipher  Cipher
	key     []byte
	mode    EncryptMode
	iv      []byte
	padding Padding
}

func NewEncryptor(cipher Cipher, key []byte, mode EncryptMode, iv []byte, padding Padding) Encryptor {
	return Encryptor{
		cipher:  cipher,
		key:     key,
		mode:    mode,
		iv:      iv,
		padding: padding,
	}
}

func (e Encryptor) Encrypt(plain []byte) ([]byte, error) {
	block, err := e.cipher(e.key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()

	plain = bytes.Copy(plain)
	plain = e.padding(plain, blockSize)

	crypted := plain

	err = e.mode.Crypt(block, e.iv, plain, crypted)
	if err != nil {
		return nil, err
	}

	return crypted, nil
}
