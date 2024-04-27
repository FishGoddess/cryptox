// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	stdhmac "crypto/hmac"
	"fmt"
	"hash"
)

func hmac(hashFunc func() hash.Hash, key []byte, bs []byte) ([]byte, error) {
	hm := stdhmac.New(hashFunc, key)

	n, err := hm.Write(bs)
	if err != nil {
		return nil, err
	}

	if n != len(bs) {
		return nil, fmt.Errorf("cryptox: hmac written n %d != len(bs) %d", n, len(bs))
	}

	return hm.Sum(nil), nil
}
