// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/FishGoddess/cryptox/rsa"
)

// go test -v -bench=^BenchmarkRSAGenerateKey1024PKCS1PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS1PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS1PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS1PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKIXPublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey1024PKCS1PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS1PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS1PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS1PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS1PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey1024PKCS8PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithGeneratePrivateKeyEncoder(rsa.X509.PKCS8PrivateKeyEncoder),
		rsa.WithGeneratePrivateKeyDecoder(rsa.X509.PKCS8PrivateKeyDecoder),
		rsa.WithGeneratePublicKeyEncoder(rsa.X509.PKCS1PublicKeyEncoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := generator.GenerateKeys(4096)
		if err != nil {
			b.Error(err)
		}
	}
}
