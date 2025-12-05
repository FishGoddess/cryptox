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

### 🚴🏻 Benchmarks

```shell
$ make bench
```

_Note: Data size is 128 bytes, ecb/cbc uses pkcs7 padding, cfb/ofb/ctr/gcm is no padding._

```
goos: linux
goarch: amd64
cpu: Intel(R) Xeon(R) CPU E5-26xx v4

BenchmarkHash_MD5-2              5402781               222.2 ns/op            32 B/op          2 allocs/op
BenchmarkHash_SHA1-2             2861774               428.6 ns/op            40 B/op          2 allocs/op
BenchmarkHash_SHA224-2           3223394               377.9 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA256-2           3195488               391.1 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA384-2           2543738               475.8 ns/op            64 B/op          2 allocs/op
BenchmarkHash_SHA512-2           2521041               484.7 ns/op            80 B/op          2 allocs/op
BenchmarkHash_CRC32IEEE-2       29772795                40.62 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ISO-2        30194895                38.81 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ECMA-2       30640298                38.88 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv32-2           76871449                14.81 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv32a-2          77299245                14.90 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv64-2           85886235                13.11 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv64a-2          88818280                13.59 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv128-2           7457739               166.9 ns/op            40 B/op          3 allocs/op
BenchmarkHash_Fnv128a-2          7051596               170.2 ns/op            40 B/op          3 allocs/op

BenchmarkHMAC_MD5-2              1137166              1080 ns/op             448 B/op          7 allocs/op
BenchmarkHMAC_SHA1-2              534306              1941 ns/op             488 B/op          7 allocs/op
BenchmarkHMAC_SHA224-2            650616              1616 ns/op             528 B/op          7 allocs/op
BenchmarkHMAC_SHA256-2            741920              1643 ns/op             528 B/op          7 allocs/op
BenchmarkHMAC_SHA384-2            521118              2165 ns/op             864 B/op          7 allocs/op
BenchmarkHMAC_SHA512-2            501279              2147 ns/op             880 B/op          7 allocs/op

BenchmarkDES_EncryptECB-2         228224              5109 ns/op             688 B/op          5 allocs/op
BenchmarkDES_EncryptCBC-2         201259              5450 ns/op             784 B/op          8 allocs/op
BenchmarkDES_EncryptCFB-2         219808              5234 ns/op             512 B/op          7 allocs/op
BenchmarkDES_EncryptOFB-2         101382             11784 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_EncryptCTR-2          97594             12126 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_DecryptECB-2         223354              4725 ns/op             304 B/op          3 allocs/op
BenchmarkDES_DecryptCBC-2         227923              5235 ns/op             400 B/op          6 allocs/op
BenchmarkDES_DecryptCFB-2         231697              4991 ns/op             384 B/op          6 allocs/op
BenchmarkDES_DecryptOFB-2          98470             11694 ns/op             888 B/op          6 allocs/op
BenchmarkDES_DecryptCTR-2          96957             12125 ns/op             888 B/op          6 allocs/op

BenchmarkDES_EncryptTripleECB-2            89923             13391 ns/op             944 B/op          5 allocs/op
BenchmarkDES_EncryptTripleCBC-2            87915             13518 ns/op            1040 B/op          8 allocs/op
BenchmarkDES_EncryptTripleCFB-2            84099             13238 ns/op             768 B/op          7 allocs/op
BenchmarkDES_EncryptTripleOFB-2            39392             30196 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_EncryptTripleCTR-2            39442             31233 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_DecryptTripleECB-2            94470             12518 ns/op             560 B/op          3 allocs/op
BenchmarkDES_DecryptTripleCBC-2            92020             12995 ns/op             656 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCFB-2            86136             12939 ns/op             640 B/op          6 allocs/op
BenchmarkDES_DecryptTripleOFB-2            39723             29703 ns/op            1144 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCTR-2            33714             31441 ns/op            1144 B/op          6 allocs/op

BenchmarkAES_EncryptECB-2        1441474               852.3 ns/op          1104 B/op          5 allocs/op
BenchmarkAES_EncryptCBC-2         906620              1127 ns/op            1616 B/op          6 allocs/op
BenchmarkAES_EncryptCFB-2        1198174              1040 ns/op             944 B/op          7 allocs/op
BenchmarkAES_EncryptOFB-2         542982              1909 ns/op            1440 B/op          7 allocs/op
BenchmarkAES_EncryptCTR-2        1678208               691.6 ns/op          1344 B/op          5 allocs/op
BenchmarkAES_EncryptGCM-2        1284980               940.5 ns/op          1616 B/op          5 allocs/op
BenchmarkAES_DecryptECB-2        1832341               670.6 ns/op           720 B/op          3 allocs/op
BenchmarkAES_DecryptCBC-2        1310142               860.3 ns/op          1232 B/op          4 allocs/op
BenchmarkAES_DecryptCFB-2        1206058               981.7 ns/op           816 B/op          6 allocs/op
BenchmarkAES_DecryptOFB-2         568182              1939 ns/op            1312 B/op          6 allocs/op
BenchmarkAES_DecryptCTR-2        1997515               602.6 ns/op          1216 B/op          4 allocs/op
BenchmarkAES_DecryptGCM-2        1393825               921.6 ns/op          1488 B/op          4 allocs/op

BenchmarkRSA_EncryptPKCS1v15-2                     22177             59262 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_EncryptOAEP-2                         21324             57993 ns/op            1672 B/op         16 allocs/op
BenchmarkRSA_DecryptPKCS1v15-2                       654           1808449 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptPKCS1v15SessionKey-2             680           1762642 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptOAEP-2                           674           1727423 ns/op             552 B/op          8 allocs/op
BenchmarkRSA_SignPKCS1v15-2                          663           1767622 ns/op             704 B/op          4 allocs/op
BenchmarkRSA_SignPSS-2                               676           1893845 ns/op            1104 B/op          9 allocs/op
BenchmarkRSA_VerifyPKCS1v15-2                      23022             50468 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_VerifyPSS-2                           20220             56627 ns/op            1520 B/op         15 allocs/op

BenchmarkRSA_GenerateKeys1024-2               60          21398224 ns/op          283350 B/op       2851 allocs/op
BenchmarkRSA_GenerateKeys2048-2               84         117753488 ns/op          600303 B/op       5459 allocs/op
BenchmarkRSA_GenerateKeys4096-2                1        1432974432 ns/op         2709912 B/op      14359 allocs/op
```

### 🎨 Contributing

If you find that something is not working as expected please open an _**issue**_.
