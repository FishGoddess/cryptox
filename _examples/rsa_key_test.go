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
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS1PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS1PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS8PKIX(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey1024PKCS1PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS1PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS1PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS1PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(4096)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey1024PKCS8PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey1024PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(1024)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey2048PKCS8PKCS1$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey2048PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(2048)
		if err != nil {
			b.Error(err)
		}
	}
}

// go test -v -bench=^BenchmarkRSAGenerateKey4096PKCS8PKIX$ -benchtime=1s rsa_key_test.go
func BenchmarkRSAGenerateKey4096PKCS8PKCS1(b *testing.B) {
	generator := rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS8PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS8PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKCS1PublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKCS1PublicKeyDecoder),
	)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateKey(4096)
		if err != nil {
			b.Error(err)
		}
	}
}
