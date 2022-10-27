package des

import (
	"testing"

	"github.com/FishGoddess/cryptox"
)

// go test -v -cover -run=^TestEncryptECB$
func TestEncryptECB(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      string([]byte{254, 185, 89, 183, 212, 100, 47, 203}),
		"123":   string([]byte{44, 56, 133, 81, 215, 244, 137, 236}),
		"你好，世界": string([]byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204}),
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECB([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		cryptoStr := string(crypted)
		if cryptoStr != expect {
			t.Errorf("plain %s: cryptoStr %+v != expect %+v", plain, crypted, []byte(expect))
		}
	}
}

// go test -v -cover -run=^TestEncryptECBHex$
func TestEncryptECBHex(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      "feb959b7d4642fcb",
		"123":   "2c388551d7f489ec",
		"你好，世界": "6d5238e774243c6474950ff0c626c6cc",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECBHex([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestEncryptECBBase64$
func TestEncryptECBBase64(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"":      "/rlZt9RkL8s=",
		"123":   "LDiFUdf0iew=",
		"你好，世界": "bVI453QkPGR0lQ/wxibGzA==",
	}

	for plain, expect := range cases {
		crypted, err := des.EncryptECBBase64([]byte(plain), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		if crypted != expect {
			t.Errorf("plain %s: crypted %s != expect %s", plain, crypted, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptECB$
func TestDecryptECB(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		string([]byte{254, 185, 89, 183, 212, 100, 47, 203}):                                     "",
		string([]byte{44, 56, 133, 81, 215, 244, 137, 236}):                                      "123",
		string([]byte{109, 82, 56, 231, 116, 36, 60, 100, 116, 149, 15, 240, 198, 38, 198, 204}): "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECB([]byte(crypted), cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptECBHex$
func TestDecryptECBHex(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"feb959b7d4642fcb":                 "",
		"2c388551d7f489ec":                 "123",
		"6d5238e774243c6474950ff0c626c6cc": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECBHex(crypted, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

// go test -v -cover -run=^TestDecryptECBBase64$
func TestDecryptECBBase64(t *testing.T) {
	des := New([]byte("12345678"))

	cases := map[string]string{
		"/rlZt9RkL8s=":             "",
		"LDiFUdf0iew=":             "123",
		"bVI453QkPGR0lQ/wxibGzA==": "你好，世界",
	}

	for crypted, expect := range cases {
		plain, err := des.DecryptECBBase64(crypted, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}

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
		crypted, err := des.EncryptCBC([]byte(plain), iv, cryptox.PKCS7())
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
		crypted, err := des.EncryptCBCHex([]byte(plain), iv, cryptox.PKCS7())
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
		crypted, err := des.EncryptCBCBase64([]byte(plain), iv, cryptox.PKCS7())
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
		plain, err := des.DecryptCBC([]byte(crypted), iv, cryptox.PKCS7())
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
		plain, err := des.DecryptCBCHex(crypted, iv, cryptox.PKCS7())
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
		plain, err := des.DecryptCBCBase64(crypted, iv, cryptox.PKCS7())
		if err != nil {
			t.Error(err)
		}

		plainStr := string(plain)
		if plainStr != expect {
			t.Errorf("crypted %s: plainStr %s != expect %s", crypted, plainStr, expect)
		}
	}
}
