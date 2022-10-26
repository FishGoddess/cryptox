package des

import (
	"crypto/des"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
)

type DES struct {
	key []byte
}

func New(key []byte) *DES {
	return &DES{
		key: key,
	}
}

func (d *DES) EncryptCBC(plain []byte, iv []byte, padder crypto.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = append(make([]byte, 0, len(plain)), plain...)

	mode := crypto.NewEncryptCBC(block, iv, padder)
	return mode.Encrypt(plain)
}

func (d *DES) EncryptCBCHex(plain []byte, iv []byte, padder crypto.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptCBCBase64(plain []byte, iv []byte, padder crypto.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptCBC(crypted []byte, iv []byte, padder crypto.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = append(make([]byte, 0, len(crypted)), crypted...)

	mode := crypto.NewDecryptCBC(block, iv, padder)
	return mode.Decrypt(crypted)
}

func (d *DES) DecryptCBCHex(crypted string, iv []byte, padder crypto.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}

func (d *DES) DecryptCBCBase64(crypted string, iv []byte, padder crypto.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}
