// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
)

// Decrypter decrypts data from bytes, hex, and base64.
type Decrypter struct {
	cipher    Cipher
	key       []byte
	mode      DecryptMode
	iv        []byte
	unPadding UnPadding
}

// NewDecrypter returns a new decrypter.
func NewDecrypter(cipher Cipher, key []byte, mode DecryptMode, iv []byte, unPadding UnPadding) Decrypter {
	return Decrypter{
		cipher:    cipher,
		key:       key,
		mode:      mode,
		iv:        iv,
		unPadding: unPadding,
	}
}

// Decrypt decrypts data to bytes.
func (d Decrypter) Decrypt(crypted Bytes) (Bytes, error) {
	block, err := d.cipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = crypted.Clone()
	plain := crypted

	err = d.mode.Crypt(block, d.iv, crypted, plain)
	if err != nil {
		return nil, err
	}

	return d.unPadding(plain, block.BlockSize())
}

// DecryptHex decrypts data in hex to bytes.
func (d Decrypter) DecryptHex(crypted string) (Bytes, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.Decrypt(decoded)
}

// DecryptBase64 decrypts base64 in hex to bytes.
func (d Decrypter) DecryptBase64(crypted string) (Bytes, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.Decrypt(decoded)
}
