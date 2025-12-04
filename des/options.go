// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package des

import (
	"github.com/FishGoddess/cryptox/bytes/encoding"
	"github.com/FishGoddess/cryptox/bytes/padding"
)

type Config struct {
	encoding encoding.Encoding
	padding  padding.Padding
}

func newConfig() *Config {
	conf := &Config{
		encoding: encoding.None{},
		padding:  padding.None{},
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

// WithZero sets zero padding to config.
func WithZero() Option {
	return func(conf *Config) {
		conf.padding = padding.Zero{}
	}
}

// WithPKCS5 sets pkcs5 padding to config.
func WithPKCS5() Option {
	return func(conf *Config) {
		conf.padding = padding.PKCS5{}
	}
}

// WithPKCS7 sets pkcs7 padding to config.
func WithPKCS7() Option {
	return func(conf *Config) {
		conf.padding = padding.PKCS7{}
	}
}
