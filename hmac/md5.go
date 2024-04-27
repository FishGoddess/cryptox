// Copyright 2024 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hmac

import (
	"crypto/md5"

	"github.com/FishGoddess/cryptox/bytes"
)

func MD5(key []byte, bs []byte) ([]byte, error) {
	return hmac(md5.New, key, bs)
}

func MD5Hex(key []byte, bs []byte) (string, error) {
	hm, err := hmac(md5.New, key, bs)
	if err != nil {
		return "", err
	}

	return bytes.Hex(hm), nil
}

func MD5Base64(key []byte, bs []byte) (string, error) {
	hm, err := hmac(md5.New, key, bs)
	if err != nil {
		return "", err
	}

	return bytes.Base64(hm), nil
}
