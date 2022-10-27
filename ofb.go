package crypto

import "crypto/cipher"

type EncryptOFB struct {
	blockSize int
	stream    cipher.Stream
}

func NewEncryptOFB(block cipher.Block, iv []byte) *EncryptOFB {
	return &EncryptOFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewOFB(block, iv),
	}
}

func (ec *EncryptOFB) Encrypt(plain []byte) []byte {
	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted
}

type DecryptOFB struct {
	blockSize int
	stream    cipher.Stream
}

func NewDecryptOFB(block cipher.Block, iv []byte) *DecryptOFB {
	return &DecryptOFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewOFB(block, iv),
	}
}

func (dc *DecryptOFB) Decrypt(crypted []byte) []byte {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return plain
}
