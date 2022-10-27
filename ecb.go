package crypto

import "crypto/cipher"

type EncryptECB struct {
	block  cipher.Block
	iv     []byte
	padder Padder
}

func NewEncryptECB(block cipher.Block, iv []byte, padder Padder) *EncryptECB {
	if len(iv) != block.BlockSize() {
		panic("cryptox.NewEncryptECB: IV length must equal block size")
	}

	return &EncryptECB{
		block:  block,
		iv:     iv,
		padder: padder,
	}
}

func (ec *EncryptECB) Encrypt(plain []byte) ([]byte, error) {
	blockSize := ec.block.BlockSize()
	plain = ec.padder.Padding(plain, blockSize)

	if len(plain)%blockSize != 0 {
		panic("cryptox.EncryptECB: input not full blocks")
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
	iv     []byte
	padder Padder
}

func NewDecryptECB(block cipher.Block, iv []byte, padder Padder) *DecryptECB {
	if len(iv) != block.BlockSize() {
		panic("cryptox.NewDecryptECB: IV length must equal block size")
	}

	return &DecryptECB{
		block:  block,
		iv:     iv,
		padder: padder,
	}
}

func (dc *DecryptECB) Decrypt(crypted []byte) ([]byte, error) {
	blockSize := dc.block.BlockSize()

	if len(crypted)%blockSize != 0 {
		panic("cryptox.DecryptECB: input not full blocks")
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
