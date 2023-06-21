// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

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
			b.Error(err)
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
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptPKCS1v15$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptPKCS1v15(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	rsaBenchData, err := publicKey.EncryptPKCS1v15(rsaBenchData)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptPKCS1v15(rsaBenchData)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptPKCS1v15SessionKey$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptPKCS1v15SessionKey(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	rsaBenchData, err := publicKey.EncryptPKCS1v15(rsaBenchData)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		err := privateKey.DecryptPKCS1v15SessionKey(rsaBenchData, nil)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSADecryptOAEP$ -benchtime=1s rsa_test.go
func BenchmarkRSADecryptOAEP(b *testing.B) {
	privateKey := rsa.MustLoadPrivateKey("rsa.key")
	publicKey := rsa.MustLoadPublicKey("rsa.pub")

	rsaBenchData, err := publicKey.EncryptOAEP(rsaBenchData, nil)
	if err != nil {
		b.Error(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := privateKey.DecryptOAEP(rsaBenchData, nil)
		if err != nil {
			b.Error(err)
		}
	}
}
