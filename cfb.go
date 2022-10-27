package crypto

import "crypto/cipher"

type EncryptCFB struct {
	blockSize int
	stream    cipher.Stream
}

func NewEncryptCFB(block cipher.Block, iv []byte) *EncryptCFB {
	return &EncryptCFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCFBEncrypter(block, iv),
	}
}

func (ec *EncryptCFB) Encrypt(plain []byte) []byte {
	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted
}

type DecryptCFB struct {
	blockSize int
	stream    cipher.Stream
}

func NewDecryptCFB(block cipher.Block, iv []byte) *DecryptCFB {
	return &DecryptCFB{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCFBDecrypter(block, iv),
	}
}

func (dc *DecryptCFB) Decrypt(crypted []byte) []byte {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return plain
}
