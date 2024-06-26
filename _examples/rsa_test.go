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

// go test -v -bench=^BenchmarkRSAEncryptPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSAEncryptPKCS1v15(b *testing.B) {
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := publicKey.EncryptPKCS1v15(rsaBenchData)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAEncryptOAEP$ -benchtime=1s rsa_test.go
func BenchmarkRSAEncryptOAEP(b *testing.B) {
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := publicKey.EncryptOAEP(rsaBenchData, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptPKCS1v15(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	encrypted, err := publicKey.EncryptPKCS1v15(rsaBenchData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptPKCS1v15(encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptPKCS1v15SessionKey$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptPKCS1v15SessionKey(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	encrypted, err := publicKey.EncryptPKCS1v15(rsaBenchData)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := privateKey.DecryptPKCS1v15SessionKey(encrypted, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptOAEP$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptOAEP(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	encrypted, err := publicKey.EncryptOAEP(rsaBenchData, nil)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptOAEP(encrypted, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSASignPSS$ -benchtime=1s rsa_test.go
func BenchmarkRSASignPSS(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	digest := hash.SHA256(rsaBenchData)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.SignPSS(digest, 4)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSASignPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSASignPKCS1v15(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
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

// go test -v -bench=^BenchmarkRSAVerifyPSS$ -benchtime=1s rsa_test.go
func BenchmarkRSAVerifyPSS(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")
	digest := hash.SHA256(rsaBenchData)

	saltLength := 4
	signed, err := privateKey.SignPSS(digest, saltLength)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = publicKey.VerifyPSS(digest, signed, saltLength)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAVerifyPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSAVerifyPKCS1v15(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")
	hashed := hash.SHA256(rsaBenchData)

	signed, err := privateKey.SignPKCS1v15(hashed)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err = publicKey.VerifyPKCS1v15(hashed, signed)
		if err != nil {
			b.Fatal(err)
		}
	}
}
