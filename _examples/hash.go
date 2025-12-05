// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/hash"
)

func main() {
	data := []byte("你好，世界")
	fmt.Printf("data: %s\n", data)

	md5 := hash.MD5(data)
	md5Hex := hash.MD5(data, hash.WithHex())
	md5Base64 := hash.MD5(data, hash.WithBase64())
	fmt.Printf("md5: %s\n", md5)
	fmt.Printf("md5 hex: %s\n", md5Hex)
	fmt.Printf("md5 base64: %s\n", md5Base64)

	sha1 := hash.SHA1(data)
	sha1Hex := hash.SHA1(data, hash.WithHex())
	sha1Base64 := hash.SHA1(data, hash.WithBase64())
	fmt.Printf("sha1: %s\n", sha1)
	fmt.Printf("sha1 hex: %s\n", sha1Hex)
	fmt.Printf("sha1 base64: %s\n", sha1Base64)

	sha224 := hash.SHA224(data)
	sha224Hex := hash.SHA224(data, hash.WithHex())
	sha224Base64 := hash.SHA224(data, hash.WithBase64())
	fmt.Printf("sha224: %s\n", sha224)
	fmt.Printf("sha224 hex: %s\n", sha224Hex)
	fmt.Printf("sha224 base64: %s\n", sha224Base64)

	sha256 := hash.SHA256(data)
	sha256Hex := hash.SHA256(data, hash.WithHex())
	sha256Base64 := hash.SHA256(data, hash.WithBase64())
	fmt.Printf("sha256: %s\n", sha256)
	fmt.Printf("sha256 hex: %s\n", sha256Hex)
	fmt.Printf("sha256 base64: %s\n", sha256Base64)

	sha384 := hash.SHA384(data)
	sha384Hex := hash.SHA384(data, hash.WithHex())
	sha384Base64 := hash.SHA384(data, hash.WithBase64())
	fmt.Printf("sha384: %s\n", sha384)
	fmt.Printf("sha384 hex: %s\n", sha384Hex)
	fmt.Printf("sha384 base64: %s\n", sha384Base64)

	sha512 := hash.SHA512(data)
	sha512Hex := hash.SHA512(data, hash.WithHex())
	sha512Base64 := hash.SHA512(data, hash.WithBase64())
	fmt.Printf("sha512: %s\n", sha512)
	fmt.Printf("sha512 hex: %s\n", sha512Hex)
	fmt.Printf("sha512 base64: %s\n", sha512Base64)

	crc32 := hash.CRC32IEEE(data)
	fmt.Printf("crc32 ieee: %d\n", crc32)

	crc64 := hash.CRC64ISO(data)
	fmt.Printf("crc64 iso: %d\n", crc64)

	crc64 = hash.CRC64ECMA(data)
	fmt.Printf("crc64 ecma: %d\n", crc64)

	fnv32 := hash.Fnv32(data)
	fmt.Printf("fnv32: %d\n", fnv32)

	fnv32a := hash.Fnv32a(data)
	fmt.Printf("fnv32a: %d\n", fnv32a)

	fnv64 := hash.Fnv64(data)
	fmt.Printf("fnv64: %d\n", fnv64)

	fnv64a := hash.Fnv64a(data)
	fmt.Printf("fnv64a: %d\n", fnv64a)

	fnv128 := hash.Fnv128(data)
	fnv128Hex := hash.Fnv128(data, hash.WithHex())
	fnv128Base64 := hash.Fnv128(data, hash.WithBase64())
	fmt.Printf("fnv128: %s\n", fnv128)
	fmt.Printf("fnv128 hex: %s\n", fnv128Hex)
	fmt.Printf("fnv128 base64: %s\n", fnv128Base64)

	fnv128a := hash.Fnv128a(data)
	fnv128aHex := hash.Fnv128a(data, hash.WithHex())
	fnv128aBase64 := hash.Fnv128a(data, hash.WithBase64())
	fmt.Printf("fnv128a: %s\n", fnv128a)
	fmt.Printf("fnv128a hex: %s\n", fnv128aHex)
	fmt.Printf("fnv128a base64: %s\n", fnv128aBase64)
}
