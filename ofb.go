// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "crypto/cipher"

type EncryptOFB struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewEncryptOFB(block cipher.Block, iv []byte, padder Padder) *EncryptOFB {
	return &EncryptOFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewOFB(block, iv),
		padder:    padder,
	}
}

func (ec *EncryptOFB) Encrypt(plain []byte) ([]byte, error) {
	plain = ec.padder.Padding(plain, ec.blockSize)

	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted, nil
}

type DecryptOFB struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewDecryptOFB(block cipher.Block, iv []byte, padder Padder) *DecryptOFB {
	return &DecryptOFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewOFB(block, iv),
		padder:    padder,
	}
}

func (dc *DecryptOFB) Decrypt(crypted []byte) ([]byte, error) {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return dc.padder.UnPadding(plain, dc.blockSize)
}
