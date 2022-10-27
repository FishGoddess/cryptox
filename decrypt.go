// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/pkg/bytes"
)

type Decryptor struct {
	cipher    Cipher
	key       []byte
	mode      DecryptMode
	iv        []byte
	unPadding UnPadding
}

func NewDecryptor(cipher Cipher, key []byte, mode DecryptMode, iv []byte, unPadding UnPadding) Decryptor {
	return Decryptor{
		cipher:    cipher,
		key:       key,
		mode:      mode,
		iv:        iv,
		unPadding: unPadding,
	}
}

func (d Decryptor) Decrypt(crypted []byte) ([]byte, error) {
	block, err := d.cipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)
	plain := crypted

	err = d.mode.Crypt(block, d.iv, crypted, plain)
	if err != nil {
		return nil, err
	}

	return d.unPadding(plain, block.BlockSize())
}
