package des

import (
	"crypto/des"

	"github.com/FishGoddess/cryptox"
	"github.com/FishGoddess/cryptox/base64"
	"github.com/FishGoddess/cryptox/hex"
	"github.com/FishGoddess/cryptox/pkg/bytes"
)

type DES struct {
	key []byte
}

func New(key []byte) *DES {
	return &DES{
		key: key,
	}
}

func (d *DES) EncryptECB(plain []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	ecb := cryptox.NewEncryptECB(block, padder)
	return ecb.Encrypt(plain)
}

func (d *DES) EncryptECBHex(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptECBBase64(plain []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptECB(plain, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptECB(crypted []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	ecb := cryptox.NewDecryptECB(block, padder)
	return ecb.Decrypt(crypted)
}

func (d *DES) DecryptECBHex(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptECB(decoded, padder)
}

func (d *DES) DecryptECBBase64(crypted string, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptECB(decoded, padder)
}

func (d *DES) EncryptCBC(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCBC(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *DES) EncryptCBCHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptCBCBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCBC(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptCBC(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCBC(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *DES) DecryptCBCHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}

func (d *DES) DecryptCBCBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCBC(decoded, iv, padder)
}

func (d *DES) EncryptCFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cfb := cryptox.NewEncryptCFB(block, iv, padder)
	return cfb.Encrypt(plain)
}

func (d *DES) EncryptCFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptCFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptCFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cfb := cryptox.NewDecryptCFB(block, iv, padder)
	return cfb.Decrypt(crypted)
}

func (d *DES) DecryptCFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCFB(decoded, iv, padder)
}

func (d *DES) DecryptCFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCFB(decoded, iv, padder)
}

func (d *DES) EncryptOFB(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptOFB(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *DES) EncryptOFBHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptOFBBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptOFB(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptOFB(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptOFB(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *DES) DecryptOFBHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptOFB(decoded, iv, padder)
}

func (d *DES) DecryptOFBBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptOFB(decoded, iv, padder)
}

func (d *DES) EncryptCTR(plain []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	plain = bytes.Copy(plain)

	cbc := cryptox.NewEncryptCTR(block, iv, padder)
	return cbc.Encrypt(plain)
}

func (d *DES) EncryptCTRHex(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return hex.Encode(crypted), nil
}

func (d *DES) EncryptCTRBase64(plain []byte, iv []byte, padder cryptox.Padder) (string, error) {
	crypted, err := d.EncryptCTR(plain, iv, padder)
	if err != nil {
		return "", err
	}

	return base64.Encode(crypted), nil
}

func (d *DES) DecryptCTR(crypted []byte, iv []byte, padder cryptox.Padder) ([]byte, error) {
	block, err := des.NewCipher(d.key)
	if err != nil {
		return nil, err
	}

	crypted = bytes.Copy(crypted)

	cbc := cryptox.NewDecryptCTR(block, iv, padder)
	return cbc.Decrypt(crypted)
}

func (d *DES) DecryptCTRHex(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := hex.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCTR(decoded, iv, padder)
}

func (d *DES) DecryptCTRBase64(crypted string, iv []byte, padder cryptox.Padder) ([]byte, error) {
	decoded, err := base64.Decode(crypted)
	if err != nil {
		return nil, err
	}

	return d.DecryptCTR(decoded, iv, padder)
}
