// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox/bytes/rand"
)

func main() {
	// We provide some rand functions for you.
	// If you want to generate some keys or ivs, just feel free to use them.
	bs := rand.Bytes(32)
	fmt.Printf("%s\n", bs)

	str := rand.String(64)
	fmt.Printf("%s\n", str)

	// Already have a byte slice? Try AppendBytes:
	bs = []byte{'a', 'b', 'c', '-'}
	bs = rand.AppendBytes(bs, 16)
	fmt.Printf("%s\n", bs)
}
