# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** is a safety kit including some common algorithms for convenience.

[阅读中文版的文档](./README.md)

### 💡 Features

* HEX/BASE64 encoding supports.
* MD5/SHA1/SHA256/SHA384/SHA512 hash supports.
* CRC/FNV hash supports.
* HMAC mixed hash supports.
* DES/3DES/AES encrypt and decrypt supports.
* RSA encrypt and decrypt supports.
* ED25519 sign supports.
* ECB/CBC/OFB/CFB/CTR/GCM mode supports.
* ZERO/PKCS5/PKCS7 padding supports.

_Check [HISTORY.md](./HISTORY.md) and [FUTURE.md](./FUTURE.md) to know about more information._

### ⚙ How to use

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [hash](_examples/hash.go)
* [hmac](_examples/hmac.go)
* [des](_examples/des.go)
* [triple_des](_examples/triple_des.go)
* [aes](_examples/aes.go)
* [rsa](_examples/rsa.go)
* [rsa_key](_examples/rsa_key.go)
* [ed25519](_examples/ed25519.go)
* [ed25519_key](_examples/ed25519_key.go)

### 🚴🏻 Benchmarks

```shell
$ make bench
```

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr/gcm is no padding._

```
goos: linux
goarch: amd64
cpu: Intel(R) Celeron(R) N5105 @ 2.00GHz

BenchmarkHash_MD5-2              5597575               213.4 ns/op            32 B/op          2 allocs/op
BenchmarkHash_SHA1-2             2825996               422.4 ns/op            40 B/op          2 allocs/op
BenchmarkHash_SHA224-2           1433598               836.6 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA256-2           1442934               849.9 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA384-2           1000000              1081 ns/op              64 B/op          2 allocs/op
BenchmarkHash_SHA512-2           1000000              1059 ns/op              80 B/op          2 allocs/op
BenchmarkHash_CRC32IEEE-2       29906313                40.18 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ISO-2        29545778                39.49 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ECMA-2       29889290                39.68 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv32-2           78830361                14.73 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv32a-2          71497038                16.22 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv64-2           59598745                19.97 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv64a-2          59059587                20.19 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv128-2           6973201               165.1 ns/op            40 B/op          3 allocs/op
BenchmarkHash_Fnv128a-2          7073341               166.8 ns/op            40 B/op          3 allocs/op

BenchmarkHMAC_MD5-2              1000000              1012 ns/op             448 B/op          7 allocs/op
BenchmarkHMAC_SHA1-2              648224              1844 ns/op             488 B/op          7 allocs/op
BenchmarkHMAC_SHA224-2            304837              3440 ns/op             528 B/op          7 allocs/op
BenchmarkHMAC_SHA256-2            303004              3446 ns/op             528 B/op          7 allocs/op
BenchmarkHMAC_SHA384-2            237002              4477 ns/op             864 B/op          7 allocs/op
BenchmarkHMAC_SHA512-2            239995              4536 ns/op             880 B/op          7 allocs/op

BenchmarkDES_EncryptECB-2         221138              5190 ns/op             688 B/op          5 allocs/op
BenchmarkDES_EncryptCBC-2         201598              5761 ns/op             784 B/op          8 allocs/op
BenchmarkDES_EncryptCFB-2         205272              5398 ns/op             512 B/op          7 allocs/op
BenchmarkDES_EncryptOFB-2          95566             12303 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_EncryptCTR-2          91220             13031 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_DecryptECB-2         220120              5090 ns/op             304 B/op          3 allocs/op
BenchmarkDES_DecryptCBC-2         206108              5399 ns/op             400 B/op          6 allocs/op
BenchmarkDES_DecryptCFB-2         211573              5244 ns/op             384 B/op          6 allocs/op
BenchmarkDES_DecryptOFB-2          93770             12217 ns/op             888 B/op          6 allocs/op
BenchmarkDES_DecryptCTR-2          92884             12603 ns/op             888 B/op          6 allocs/op

BenchmarkDES_EncryptTripleECB-2            84774             13861 ns/op             944 B/op          5 allocs/op
BenchmarkDES_EncryptTripleCBC-2            81261             14256 ns/op            1040 B/op          8 allocs/op
BenchmarkDES_EncryptTripleCFB-2            83955             13716 ns/op             768 B/op          7 allocs/op
BenchmarkDES_EncryptTripleOFB-2            37346             31841 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_EncryptTripleCTR-2            36417             32358 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_DecryptTripleECB-2            83520             13789 ns/op             560 B/op          3 allocs/op
BenchmarkDES_DecryptTripleCBC-2            80302             14148 ns/op             656 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCFB-2            83056             13656 ns/op             640 B/op          6 allocs/op
BenchmarkDES_DecryptTripleOFB-2            37310             31640 ns/op            1144 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCTR-2            36788             32697 ns/op            1144 B/op          6 allocs/op

BenchmarkAES_EncryptECB-2        1820994               654.2 ns/op          1104 B/op          5 allocs/op
BenchmarkAES_EncryptCBC-2        1284600               940.0 ns/op          1616 B/op          6 allocs/op
BenchmarkAES_EncryptCFB-2        1432046               835.8 ns/op           944 B/op          7 allocs/op
BenchmarkAES_EncryptOFB-2         869138              1368 ns/op            1440 B/op          7 allocs/op
BenchmarkAES_EncryptCTR-2        1811223               637.3 ns/op          1344 B/op          5 allocs/op
BenchmarkAES_EncryptGCM-2        1418142               864.2 ns/op          1616 B/op          5 allocs/op
BenchmarkAES_DecryptECB-2        2323849               521.4 ns/op           720 B/op          3 allocs/op
BenchmarkAES_DecryptCBC-2        1587555               766.5 ns/op          1232 B/op          4 allocs/op
BenchmarkAES_DecryptCFB-2        1570035               757.0 ns/op           816 B/op          6 allocs/op
BenchmarkAES_DecryptOFB-2         921681              1294 ns/op            1312 B/op          6 allocs/op
BenchmarkAES_DecryptCTR-2        2102096               582.7 ns/op          1216 B/op          4 allocs/op
BenchmarkAES_DecryptGCM-2        1443639               842.6 ns/op          1488 B/op          4 allocs/op

BenchmarkRSA_EncryptPKCS1v15-2                     13644             86674 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_EncryptOAEP-2                         12495             94785 ns/op            1672 B/op         16 allocs/op
BenchmarkRSA_DecryptPKCS1v15-2                       457           2652679 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptPKCS1v15SessionKey-2             457           2598934 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptOAEP-2                           458           2622676 ns/op             552 B/op          8 allocs/op
BenchmarkRSA_SignPKCS1v15-2                          441           2695286 ns/op             704 B/op          4 allocs/op
BenchmarkRSA_SignPSS-2                               446           2698425 ns/op            1104 B/op          9 allocs/op
BenchmarkRSA_VerifyPKCS1v15-2                      14086             84782 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_VerifyPSS-2                           12570             94880 ns/op            1520 B/op         15 allocs/op

BenchmarkRSA_GenerateKeys1024-2               78          19520517 ns/op          254085 B/op       2557 allocs/op
BenchmarkRSA_GenerateKeys2048-2               22         171717702 ns/op          638040 B/op       5801 allocs/op
BenchmarkRSA_GenerateKeys4096-2                2        2367288428 ns/op         2895288 B/op      15817 allocs/op

BenchmarkED25519_Sign-2            20478             58128 ns/op             112 B/op          2 allocs/op
BenchmarkED25519_Verify-2           8204            144994 ns/op              48 B/op          1 allocs/op

BenchmarkED25519_GenerateKeys-2            26103             45966 ns/op             208 B/op          4 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.
