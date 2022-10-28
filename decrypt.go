// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
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

	crypted = copyBytes(crypted)
	plain := crypted

	err = d.mode.Crypt(block, d.iv, crypted, plain)
	if err != nil {
		return nil, err
	}

	return d.unPadding(plain, block.BlockSize())
}

func (d Decryptor) DecryptHex(crypted string) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.Decrypt(decoded)
}

func (d Decryptor) DecryptBase64(crypted string) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.Decrypt(decoded)
}
