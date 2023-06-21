// Copyright 2023 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import (
	"testing"
)

// go test -v -cover -run=^TestPaddingAndUnPaddingNone$
func TestPaddingAndUnPaddingNone(t *testing.T) {
	blockSize := 8

	cases := map[string]string{
		string([]byte{}):                                               string([]byte{}),
		string([]byte{1, 2, 3, 4, 5}):                                  string([]byte{1, 2, 3, 4, 5}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}):                         string([]byte{1, 2, 3, 4, 5, 6, 7, 8}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}),
	}

	for data, expect := range cases {
		padding := PaddingNone(FromString(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", FromString(data), padding, FromString(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingNone(FromString(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", FromString(expect), unPadding, FromString(data))
		}
	}
}

// go test -v -cover -run=^TestPaddingAndUnPaddingZero$
func TestPaddingAndUnPaddingZero(t *testing.T) {
	blockSize := 8

	cases := map[string]string{
		string([]byte{}):                                               string([]byte{0, 0, 0, 0, 0, 0, 0, 0}),
		string([]byte{1, 2, 3, 4, 5}):                                  string([]byte{1, 2, 3, 4, 5, 0, 0, 0}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}):                         string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}),
	}

	for data, expect := range cases {
		padding := PaddingZero(FromString(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", FromString(data), padding, FromString(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingZero(FromString(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", FromString(expect), unPadding, FromString(data))
		}
	}
}

// go test -v -cover -run=^TestPaddingAndUnPaddingPKCS5$
func TestPaddingAndUnPaddingPKCS5(t *testing.T) {
	blockSize := 8

	cases := map[string]string{
		string([]byte{}):                                               string([]byte{8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5}):                                  string([]byte{1, 2, 3, 4, 5, 3, 3, 3}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}):                         string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
	}

	for data, expect := range cases {
		padding := PaddingPKCS5(FromString(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", FromString(data), padding, FromString(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingPKCS5(FromString(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", FromString(expect), unPadding, FromString(data))
		}
	}
}

// go test -v -cover -run=^TestPaddingAndUnPaddingPKCS7$
func TestPaddingAndUnPaddingPKCS7(t *testing.T) {
	blockSize := 8

	cases := map[string]string{
		string([]byte{}):                                               string([]byte{8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5}):                                  string([]byte{1, 2, 3, 4, 5, 3, 3, 3}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8}):                         string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
		string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8}): string([]byte{1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8}),
	}

	for data, expect := range cases {
		padding := PaddingPKCS7(FromString(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", FromString(data), padding, FromString(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingPKCS7(FromString(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", FromString(expect), unPadding, FromString(data))
		}
	}
}
