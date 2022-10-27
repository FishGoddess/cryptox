package cryptox

import "crypto/cipher"

type EncryptCTR struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewEncryptCTR(block cipher.Block, iv []byte, padder Padder) *EncryptCTR {
	return &EncryptCTR{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCTR(block, iv),
		padder:    padder,
	}
}

func (ec *EncryptCTR) Encrypt(plain []byte) ([]byte, error) {
	plain = ec.padder.Padding(plain, ec.blockSize)

	crypted := plain
	ec.stream.XORKeyStream(crypted, plain)

	return crypted, nil
}

type DecryptCTR struct {
	blockSize int
	stream    cipher.Stream
	padder    Padder
}

func NewDecryptCTR(block cipher.Block, iv []byte, padder Padder) *DecryptCTR {
	return &DecryptCTR{
		blockSize: block.BlockSize(),
		stream:    cipher.NewCTR(block, iv),
		padder:    padder,
	}
}

func (dc *DecryptCTR) Decrypt(crypted []byte) ([]byte, error) {
	plain := crypted
	dc.stream.XORKeyStream(plain, crypted)

	return dc.padder.UnPadding(plain, dc.blockSize)
}
