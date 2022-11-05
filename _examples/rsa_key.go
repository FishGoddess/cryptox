// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/rsa"
)

func main() {
	// Generate a 2048 bits key.
	// See rsa.KeyOption.
	privateKey, publicKey, err := rsa.GenerateKeys(2048)
	if err != nil {
		panic(err)
	}

	fmt.Println(privateKey)
	fmt.Println(publicKey)

	// Try WriteToFile if you want to write your key to file.
	n, err := privateKey.Encoded().WriteToFile("rsa.key")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Write %d bytes to private key file\n", n)

	// Try WriteToFile if you want to write your key to file.
	n, err = publicKey.Encoded().WriteToFile("rsa.pub")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Write %d bytes to public key file\n", n)

	loadedPrivateKey, err := rsa.LoadPrivateKey("rsa.key")
	if err != nil {
		panic(err)
	}

	loadedPublicKey, err := rsa.LoadPublicKey("rsa.pub")
	if err != nil {
		panic(err)
	}

	fmt.Println(loadedPrivateKey)
	fmt.Println(loadedPublicKey)
}
