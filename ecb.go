package cryptox

import (
	"crypto/cipher"
	"fmt"
)

type EncryptECB struct {
	block  cipher.Block
	padder Padder
}

func NewEncryptECB(block cipher.Block, padder Padder) *EncryptECB {
	return &EncryptECB{
		block:  block,
		padder: padder,
	}
}

func (ec *EncryptECB) Encrypt(plain []byte) ([]byte, error) {
	blockSize := ec.block.BlockSize()
	plain = ec.padder.Padding(plain, blockSize)

	if len(plain)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox.EncryptECB: len(plain) %d %% blockSize %d != 0", len(plain), blockSize)
	}

	crypted := plain
	start := 0
	end := blockSize

	for end <= len(plain) {
		ec.block.Encrypt(crypted[start:end], plain[start:end])

		start += blockSize
		end += blockSize
	}

	return crypted, nil
}

type DecryptECB struct {
	block  cipher.Block
	padder Padder
}

func NewDecryptECB(block cipher.Block, padder Padder) *DecryptECB {
	return &DecryptECB{
		block:  block,
		padder: padder,
	}
}

func (dc *DecryptECB) Decrypt(crypted []byte) ([]byte, error) {
	blockSize := dc.block.BlockSize()

	if len(crypted)%blockSize != 0 {
		return nil, fmt.Errorf("cryptox.DecryptECB: len(crypted) %d %% blockSize %d != 0", len(crypted), blockSize)
	}

	plain := crypted
	start := 0
	end := blockSize

	for end <= len(plain) {
		dc.block.Decrypt(crypted[start:end], plain[start:end])

		start += blockSize
		end += blockSize
	}

	return dc.padder.UnPadding(plain, blockSize)
}
