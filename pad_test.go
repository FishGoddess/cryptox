// Copyright 2022 FishGoddess. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package cryptox

import "testing"

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
		padding := PaddingNone([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingNone([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
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
		padding := PaddingZero([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingZero([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
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
		padding := PaddingPKCS5([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingPKCS5([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
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
		padding := PaddingPKCS7([]byte(data), blockSize)
		if string(padding) != expect {
			t.Errorf("data %+v: padding %+v != expect %s", []byte(data), padding, []byte(expect))
		}
	}

	for data, expect := range cases {
		unPadding, err := UnPaddingPKCS7([]byte(expect), blockSize)
		if err != nil {
			t.Error(err)
		}

		if string(unPadding) != data {
			t.Errorf("expect %+v: unPadding %+v != data %+v", []byte(expect), unPadding, []byte(data))
		}
	}
}
