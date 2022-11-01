// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	// Use NewKeyGenerator to generate a key including private and public.
	generator := rsa.NewKeyGenerator()

	// Also, you can use an option to choose your encoder and decoder.
	generator = rsa.NewKeyGenerator(
		rsa.WithPrivateKeyEncoder(rsa.PKCS1PrivateKeyEncoder),
		rsa.WithPrivateKeyDecoder(rsa.PKCS1PrivateKeyDecoder),
		rsa.WithPublicKeyEncoder(rsa.PKIXPublicKeyEncoder),
		rsa.WithPublicKeyDecoder(rsa.PKIXPublicKeyDecoder),
	)

	// Generate a 2048 bits key.
	key, err := generator.GenerateKey(2048)
	if err != nil {
		panic(err)
	}

	fmt.Println(key.Private)
	fmt.Println(key.Public)

	// Try WriteToFile if you want to write your key to file.
	n, err := key.WriteToFile("rsa.key", "rsa.pub")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Write %d bytes to file\n", n)
}
