// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import "github.com/FishGoddess/cryptox/bytes/rand"

// Nonce returns a standard nonce for gcm.
func Nonce() []byte {
	nonceSize := 12
	return rand.Bytes(nonceSize)
}
