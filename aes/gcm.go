// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package aes

import (
	"github.com/FishGoddess/cryptox"
)

// GenerateGCMNonce generates a standard nonce for gcm.
func GenerateGCMNonce() cryptox.Bytes {
	standardNonceSize := 12
	return cryptox.GenerateBytes(standardNonceSize)
}
