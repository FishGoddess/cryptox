// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"

	"github.com/FishGoddess/cryptox"
)

func main() {
	// We provide some rand functions for you.
	// If you want to generate some keys or ivs, just feel free to use them.
	bs := cryptox.GenerateBytes(32)
	fmt.Println(bs)

	str := cryptox.GenerateString(64)
	fmt.Println(str)

	// Already have a byte slice? Try AppendBytes:
	bs = make(cryptox.Bytes, 0, 16)
	bs = cryptox.AppendBytes(bs, 16)
	fmt.Println(bs)
}
