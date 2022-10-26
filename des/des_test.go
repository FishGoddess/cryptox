package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestEncryptCBC$
func TestEncryptCBC(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      string([]byte{205, 172, 198, 131, 218, 176, 175, 188}),
		"123":   string([]byte{243, 126, 30, 174, 181, 95, 17, 128}),
		"你好，世界": string([]byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBC([]byte(plain), iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestEncryptCBCHex$
func TestEncryptCBCHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "cdacc683dab0afbc",
		"123":   "f37e1eaeb55f1180",
		"你好，世界": "b96c1d702a47a9f03ed79c9a91586e0a",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBCHex([]byte(plain), iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestEncryptCBCBase64$
func TestEncryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"":      "zazGg9qwr7w=",
		"123":   "834errVfEYA=",
		"你好，世界": "uWwdcCpHqfA+15yakVhuCg==",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptCBCBase64([]byte(plain), iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptCBC$
func TestDecryptCBC(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		string([]byte{205, 172, 198, 131, 218, 176, 175, 188}):                                   "",
		string([]byte{243, 126, 30, 174, 181, 95, 17, 128}):                                      "123",
		string([]byte{185, 108, 29, 112, 42, 71, 169, 240, 62, 215, 156, 154, 145, 88, 110, 10}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBC([]byte(crypted), iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptCBCHex$
func TestDecryptCBCHex(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"cdacc683dab0afbc":                 "",
		"f37e1eaeb55f1180":                 "123",
		"b96c1d702a47a9f03ed79c9a91586e0a": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBCHex(crypted, iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptCBCBase64$
func TestDecryptCBCBase64(t *testing.T) {
	des := New([]byte("12345678"))
	iv := []byte("87654321")

	cases := map[string]string{
		"zazGg9qwr7w=":             "",
		"834errVfEYA=":             "123",
		"uWwdcCpHqfA+15yakVhuCg==": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptCBCBase64(crypted, iv, crypto.PKCS5())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}
