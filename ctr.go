package crypto

import "crypto/cipher"

type EncryptCTR struct {
	blockSize int
	stream    cipher.Stream
}

func NewEncryptCTR(block cipher.Block, iv []byte) *EncryptCTR {
	return &EncryptCTR{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCTR(block, iv),
	}
}

func (ec *EncryptCTR) Encrypt(plain []byte) []byte {
	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted
}

type DecryptCTR struct {
	blockSize int
	stream    cipher.Stream
}

func NewDecryptCTR(block cipher.Block, iv []byte) *DecryptCTR {
	return &DecryptCTR{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCTR(block, iv),
	}
}

func (dc *DecryptCTR) Decrypt(crypted []byte) []byte {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return plain
}
