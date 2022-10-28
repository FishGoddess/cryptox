// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

type DES struct {
	cryptox.Encryptor
	cryptox.Decryptor
}

func ECB(key []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) DES {
	return DES{
		Encryptor: cryptox.NewEncryptor(cryptox.DES, key, cryptox.EncryptECB, nil, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.DES, key, cryptox.DecryptECB, nil, unPadding),
	}
}

func CBC(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) DES {
	return DES{
		Encryptor: cryptox.NewEncryptor(cryptox.DES, key, cryptox.EncryptCBC, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.DES, key, cryptox.DecryptCBC, iv, unPadding),
	}
}

func CFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) DES {
	return DES{
		Encryptor: cryptox.NewEncryptor(cryptox.DES, key, cryptox.EncryptCFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.DES, key, cryptox.DecryptCFB, iv, unPadding),
	}
}

func OFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) DES {
	return DES{
		Encryptor: cryptox.NewEncryptor(cryptox.DES, key, cryptox.EncryptOFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.DES, key, cryptox.DecryptOFB, iv, unPadding),
	}
}

func CTR(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) DES {
	return DES{
		Encryptor: cryptox.NewEncryptor(cryptox.DES, key, cryptox.EncryptCTR, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.DES, key, cryptox.DecryptCTR, iv, unPadding),
	}
}
