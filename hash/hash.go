// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"crypto/hmac"

	"github.com/FishGoddess/cryptox"
)

func MD5(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.MD5).Hash(data)
	return bs
}

func SHA1(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.SHA1).Hash(data)
	return bs
}

func SHA224(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.SHA224).Hash(data)
	return bs
}

func SHA256(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.SHA256).Hash(data)
	return bs
}

func SHA384(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.SHA384).Hash(data)
	return bs
}

func SHA512(data cryptox.Bytes) cryptox.Bytes {
	bs, _ := cryptox.NewHasher(cryptox.SHA512).Hash(data)
	return bs
}

func HMAC(hash cryptox.Hash, key cryptox.Bytes, data cryptox.Bytes) cryptox.Bytes {
	h := hmac.New(hash, key)

	// It should return a nil error forever.
	h.Write(data)
	return h.Sum(nil)
}
