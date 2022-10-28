// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import "github.com/FishGoddess/cryptox"

type TripleDES struct {
	cryptox.Encryptor
	cryptox.Decryptor
}

func WithTripleECB(key []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) TripleDES {
	return TripleDES{
		Encryptor: cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptECB, nil, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptECB, nil, unPadding),
	}
}

func WithTripleCBC(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) TripleDES {
	return TripleDES{
		Encryptor: cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCBC, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCBC, iv, unPadding),
	}
}

func WithTripleCFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) TripleDES {
	return TripleDES{
		Encryptor: cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCFB, iv, unPadding),
	}
}

func WithTripleOFB(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) TripleDES {
	return TripleDES{
		Encryptor: cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptOFB, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptOFB, iv, unPadding),
	}
}

func WithTripleCTR(key []byte, iv []byte, padding cryptox.Padding, unPadding cryptox.UnPadding) TripleDES {
	return TripleDES{
		Encryptor: cryptox.NewEncryptor(cryptox.TripleDES, key, cryptox.EncryptCTR, iv, padding),
		Decryptor: cryptox.NewDecryptor(cryptox.TripleDES, key, cryptox.DecryptCTR, iv, unPadding),
	}
}