// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import "github.com/FishGoddess/cryptox"

type AES struct {
	cryptox.Encryptor
	cryptox.Decryptor
}

func ECB(key []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) AES {
	return AES{
		Encryptor: cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptECB, nil, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptECB, nil, unPadding),
	}
}

func CBC(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) AES {
	return AES{
		Encryptor: cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCBC, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCBC, iv, unPadding),
	}
}

func CFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) AES {
	return AES{
		Encryptor: cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCFB, iv, unPadding),
	}
}

func OFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) AES {
	return AES{
		Encryptor: cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptOFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptOFB, iv, unPadding),
	}
}

func CTR(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) AES {
	return AES{
		Encryptor: cryptox.NewEncryptor(cryptox.AES, key, cryptox.EncryptCTR, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.AES, key, cryptox.DecryptCTR, iv, unPadding),
	}
}
