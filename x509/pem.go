// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package x509

import (
	"bytes"
	"encoding/pem"
	"errors"
)

func encode(blockType string, blockBytes []byte) (bs []byte, err error) {
	block := &pem.Block{Type: blockType, Bytes: blockBytes}

	var buffer bytes.Buffer
	if err := pem.Encode(&buffer, block); err != nil {
		return nil, err
	}

	bs = buffer.Bytes()
	return bs, nil
}

func decode(bs []byte) (blockType string, blockBytes []byte, err error) {
	block, _ := pem.Decode(bs)
	if block == nil {
		return "", nil, errors.New("cryptox/x509: decode block is nil")
	}

	blockType, blockBytes = block.Type, block.Bytes
	return blockType, blockBytes, nil
}
