// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/hash"
	"github.com/FishGoddess/cryptox/rsa"
)

var (
	rsaBenchData = []byte("你好，世界")
)

// go test -v -bench=^BenchmarkRSA_EncryptPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSA_EncryptPKCS1v15(b *testing.B) {
	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := publicKey.EncryptPKCS1v15(rsaBenchData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_EncryptOAEP$ -benchtime=1s rsa_test.go
func BenchmarkRSA_EncryptOAEP(b *testing.B) {
	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := publicKey.EncryptOAEP(rsaBenchData, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_DecryptPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSA_DecryptPKCS1v15(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	encrypt, err := publicKey.EncryptPKCS1v15(rsaBenchData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptPKCS1v15(encrypt)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_DecryptPKCS1v15SessionKey$ -benchtime=1s rsa_test.go
func BenchmarkRSA_DecryptPKCS1v15SessionKey(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	sessionKey := []byte("12345678876543211234567887654321")

	encrypt, err := publicKey.EncryptPKCS1v15(sessionKey)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := privateKey.DecryptPKCS1v15SessionKey(encrypt, sessionKey)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_DecryptOAEP$ -benchtime=1s rsa_test.go
func BenchmarkRSA_DecryptOAEP(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	encrypt, err := publicKey.EncryptOAEP(rsaBenchData, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptOAEP(encrypt, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_SignPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSA_SignPKCS1v15(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	hashed := hash.SHA256(rsaBenchData)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.SignPKCS1v15(hashed)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_SignPSS$ -benchtime=1s rsa_test.go
func BenchmarkRSA_SignPSS(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	digest := hash.SHA256(rsaBenchData)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.SignPSS(digest)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_VerifyPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSA_VerifyPKCS1v15(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	hashed := hash.SHA256(rsaBenchData)

	sign, err := privateKey.SignPKCS1v15(hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = publicKey.VerifyPKCS1v15(hashed, sign)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSA_VerifyPSS$ -benchtime=1s rsa_test.go
func BenchmarkRSA_VerifyPSS(b *testing.B) {
	privateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		b.Fatal(err)
	}

	publicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		b.Fatal(err)
	}

	digest := hash.SHA256(rsaBenchData)

	sign, err := privateKey.SignPSS(digest)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = publicKey.VerifyPSS(digest, sign)
		if err != nil {
			b.Fatal(err)
		}
	}
}
