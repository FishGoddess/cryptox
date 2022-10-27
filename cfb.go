// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "crypto/cipher"

type EncryptCFB struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewEncryptCFB(block cipher.Block, iv []byte, padder Padder) *EncryptCFB {
	return &EncryptCFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCFBEncrypter(block, iv),
		padder:    padder,
	}
}

func (ec *EncryptCFB) Encrypt(plain []byte) ([]byte, error) {
	plain = ec.padder.Padding(plain, ec.blockSize)

	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted, nil
}

type DecryptCFB struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewDecryptCFB(block cipher.Block, iv []byte, padder Padder) *DecryptCFB {
	return &DecryptCFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCFBDecrypter(block, iv),
		padder:    padder,
	}
}

func (dc *DecryptCFB) Decrypt(crypted []byte) ([]byte, error) {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return dc.padder.UnPadding(plain, dc.blockSize)
}
