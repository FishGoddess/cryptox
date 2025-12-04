// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package hash

import (
	"github.com/FishGoddess/cryptox/bytes/encoding"
)

type Config struct {
	encoding encoding.Encoding
}

func newConfig() *Config {
	conf := &Config{
		encoding: encoding.None{},
	}

	return conf
}

func (c *Config) Apply(opts ...Option) *Config {
	for _, opt := range opts {
		opt(c)
	}

	return c
}

type Option func(conf *Config)

// WithHex sets hex encoding to config.
func WithHex() Option {
	return func(conf *Config) {
		conf.encoding = encoding.Hex{}
	}
}

// WithBase64 sets base64 encoding to config.
func WithBase64() Option {
	return func(conf *Config) {
		conf.encoding = encoding.Base64{}
	}
}
