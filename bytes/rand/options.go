// Copyright 2025 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package rand

type Config struct {
	weak bool
}

func newConfig() *Config {
	conf := &Config{
		weak: false,
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

// WithWeak sets weak to config.
func WithWeak() Option {
	return func(conf *Config) {
		conf.weak = true
	}
}
