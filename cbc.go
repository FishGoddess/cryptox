// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "crypto/cipher"

type EncryptCBC struct {
	blockSize int
	mode      cipher.BlockMode
	padder    Padder
}

func NewEncryptCBC(block cipher.Block, iv []byte, padder Padder) *EncryptCBC {
	return &EncryptCBC{
		blockSize: block.BlockSize(),
		mode:      cipher.NewCBCEncrypter(block, iv),
		padder:    padder,
	}
}

func (ec *EncryptCBC) Encrypt(plain []byte) ([]byte, error) {
	plain = ec.padder.Padding(plain, ec.blockSize)

	crypted := plain
	ec.mode.CryptBlocks(crypted, plain)

	return crypted, nil
}

type DecryptCBC struct {
	blockSize int
	mode      cipher.BlockMode
	padder    Padder
}

func NewDecryptCBC(block cipher.Block, iv []byte, padder Padder) *DecryptCBC {
	return &DecryptCBC{
		blockSize: block.BlockSize(),
		mode:      cipher.NewCBCDecrypter(block, iv),
		padder:    padder,
	}
}

func (dc *DecryptCBC) Decrypt(crypted []byte) ([]byte, error) {
	plain := crypted
	dc.mode.CryptBlocks(plain, crypted)

	return dc.padder.UnPadding(plain, dc.blockSize)
}
