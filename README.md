# 🔒 Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** 是使用 Go 开发的安全套件，基于标准库封装了一些常用算法，主要为了方便使用。

[Read me in English](./README.en.md)

### 💡 功能特性

* 支持 HEX/BASE64 等编解码算法。
* 支持 MD5/SHA1/SHA256/SHA384/SHA512 等散列算法。
* 支持 CRC/FNV 等散列算法。
* 支持 HMAC 混合基础的散列算法。
* 支持 DES/3DES/AES 等对称加密算法。
* 支持 RSA 等非对称加密算法。
* 支持 ED25519 等签名算法。
* 支持 ECB/CBC/OFB/CFB/CTR/GCM 等分组模式。
* 支持 ZERO/PKCS5/PKCS7 等字节填充方式。

_历史版本的特性请查看 [HISTORY.md](./HISTORY.md)。未来版本的新特性和计划请查看 [FUTURE.md](./FUTURE.md)。_

### ⚙ 使用方式

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

### 🚴🏻 性能测试

```shell
$ make bench
```

_注：数据为 128 字节，ecb/cbc 为 pkcs7 填充，cfb/ofb/ctr/gcm 为不填充。_

```
goos: linux
goarch: amd64
cpu: AMD Ryzen 5 4600H with Radeon Graphics

BenchmarkHash_MD5
BenchmarkHash_MD5-6              5070510               240.2 ns/op            32 B/op          2 allocs/op
BenchmarkHash_SHA1
BenchmarkHash_SHA1-6             5539497               215.7 ns/op            40 B/op          2 allocs/op
BenchmarkHash_SHA224
BenchmarkHash_SHA224-6           5123552               235.6 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA256
BenchmarkHash_SHA256-6           5242689               217.1 ns/op            48 B/op          2 allocs/op
BenchmarkHash_SHA384
BenchmarkHash_SHA384-6           3734816               304.0 ns/op            64 B/op          2 allocs/op
BenchmarkHash_SHA512
BenchmarkHash_SHA512-6           3821562               307.6 ns/op            80 B/op          2 allocs/op
BenchmarkHash_CRC32IEEE
BenchmarkHash_CRC32IEEE-6       45545049                25.13 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ISO
BenchmarkHash_CRC64ISO-6        51333805                23.21 ns/op            0 B/op          0 allocs/op
BenchmarkHash_CRC64ECMA
BenchmarkHash_CRC64ECMA-6       51016614                23.36 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv32
BenchmarkHash_Fnv32-6           127631564                9.457 ns/op           0 B/op          0 allocs/op
BenchmarkHash_Fnv32a
BenchmarkHash_Fnv32a-6          128052213                9.362 ns/op           0 B/op          0 allocs/op
BenchmarkHash_Fnv64
BenchmarkHash_Fnv64-6           100000000               10.47 ns/op            0 B/op          0 allocs/op
BenchmarkHash_Fnv64a
BenchmarkHash_Fnv64a-6          125610295                9.380 ns/op           0 B/op          0 allocs/op
BenchmarkHash_Fnv128
BenchmarkHash_Fnv128-6          11149087               111.7 ns/op            40 B/op          3 allocs/op
BenchmarkHash_Fnv128a
BenchmarkHash_Fnv128a-6         10611957               112.3 ns/op            40 B/op          3 allocs/op

BenchmarkHMAC_MD5
BenchmarkHMAC_MD5-6              1530267               789.7 ns/op           448 B/op          7 allocs/op
BenchmarkHMAC_SHA1
BenchmarkHMAC_SHA1-6             1647916               697.1 ns/op           488 B/op          7 allocs/op
BenchmarkHMAC_SHA224
BenchmarkHMAC_SHA224-6           1635188               730.3 ns/op           528 B/op          7 allocs/op
BenchmarkHMAC_SHA256
BenchmarkHMAC_SHA256-6           1646613               683.0 ns/op           528 B/op          7 allocs/op
BenchmarkHMAC_SHA384
BenchmarkHMAC_SHA384-6            715630              1495 ns/op             864 B/op          7 allocs/op
BenchmarkHMAC_SHA512
BenchmarkHMAC_SHA512-6            809736              1494 ns/op             880 B/op          7 allocs/op

BenchmarkDES_EncryptECB
BenchmarkDES_EncryptECB-6         420600              2823 ns/op             688 B/op          5 allocs/op
BenchmarkDES_EncryptCBC
BenchmarkDES_EncryptCBC-6         397590              3002 ns/op             784 B/op          8 allocs/op
BenchmarkDES_EncryptCFB
BenchmarkDES_EncryptCFB-6         405061              2848 ns/op             512 B/op          7 allocs/op
BenchmarkDES_EncryptOFB
BenchmarkDES_EncryptOFB-6         169711              7174 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_EncryptCTR
BenchmarkDES_EncryptCTR-6         157942              7478 ns/op            1016 B/op          7 allocs/op
BenchmarkDES_DecryptECB
BenchmarkDES_DecryptECB-6         461720              2607 ns/op             304 B/op          3 allocs/op
BenchmarkDES_DecryptCBC
BenchmarkDES_DecryptCBC-6         408536              2804 ns/op             400 B/op          6 allocs/op
BenchmarkDES_DecryptCFB
BenchmarkDES_DecryptCFB-6         413971              2786 ns/op             384 B/op          6 allocs/op
BenchmarkDES_DecryptOFB
BenchmarkDES_DecryptOFB-6         170248              7046 ns/op             888 B/op          6 allocs/op
BenchmarkDES_DecryptCTR
BenchmarkDES_DecryptCTR-6         161248              7321 ns/op             888 B/op          6 allocs/op

BenchmarkDES_EncryptTripleECB
BenchmarkDES_EncryptTripleECB-6           168051              7112 ns/op             944 B/op          5 allocs/op
BenchmarkDES_EncryptTripleCBC
BenchmarkDES_EncryptTripleCBC-6           158871              7412 ns/op            1040 B/op          8 allocs/op
BenchmarkDES_EncryptTripleCFB
BenchmarkDES_EncryptTripleCFB-6           167058              6998 ns/op             768 B/op          7 allocs/op
BenchmarkDES_EncryptTripleOFB
BenchmarkDES_EncryptTripleOFB-6            66528             17862 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_EncryptTripleCTR
BenchmarkDES_EncryptTripleCTR-6            64724             18296 ns/op            1272 B/op          7 allocs/op
BenchmarkDES_DecryptTripleECB
BenchmarkDES_DecryptTripleECB-6           171658              6785 ns/op             560 B/op          3 allocs/op
BenchmarkDES_DecryptTripleCBC
BenchmarkDES_DecryptTripleCBC-6           168668              7094 ns/op             656 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCFB
BenchmarkDES_DecryptTripleCFB-6           168859              6877 ns/op             640 B/op          6 allocs/op
BenchmarkDES_DecryptTripleOFB
BenchmarkDES_DecryptTripleOFB-6            67381             17778 ns/op            1144 B/op          6 allocs/op
BenchmarkDES_DecryptTripleCTR
BenchmarkDES_DecryptTripleCTR-6            65196             18240 ns/op            1144 B/op          6 allocs/op

BenchmarkAES_EncryptECB
BenchmarkAES_EncryptECB-6        2376384               511.6 ns/op          1104 B/op          5 allocs/op
BenchmarkAES_EncryptCBC
BenchmarkAES_EncryptCBC-6        1701298               744.7 ns/op          1616 B/op          6 allocs/op
BenchmarkAES_EncryptCFB
BenchmarkAES_EncryptCFB-6        1615058               758.4 ns/op           944 B/op          7 allocs/op
BenchmarkAES_EncryptOFB
BenchmarkAES_EncryptOFB-6         816039              1267 ns/op            1440 B/op          7 allocs/op
BenchmarkAES_EncryptCTR
BenchmarkAES_EncryptCTR-6        2617604               508.9 ns/op          1344 B/op          5 allocs/op
BenchmarkAES_EncryptGCM
BenchmarkAES_EncryptGCM-6        1301576               984.7 ns/op          1616 B/op          5 allocs/op
BenchmarkAES_DecryptECB
BenchmarkAES_DecryptECB-6        1914866               619.2 ns/op           720 B/op          3 allocs/op
BenchmarkAES_DecryptCBC
BenchmarkAES_DecryptCBC-6        1384694               876.5 ns/op          1232 B/op          4 allocs/op
BenchmarkAES_DecryptCFB
BenchmarkAES_DecryptCFB-6        1318628               769.4 ns/op           816 B/op          6 allocs/op
BenchmarkAES_DecryptOFB
BenchmarkAES_DecryptOFB-6         877932              1178 ns/op            1312 B/op          6 allocs/op
BenchmarkAES_DecryptCTR
BenchmarkAES_DecryptCTR-6        2969346               410.3 ns/op          1216 B/op          4 allocs/op
BenchmarkAES_DecryptGCM
BenchmarkAES_DecryptGCM-6        1709960               894.5 ns/op          1488 B/op          4 allocs/op

BenchmarkRSA_EncryptPKCS1v15-6                     23125             52022 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_EncryptOAEP
BenchmarkRSA_EncryptOAEP-6                         33315             36115 ns/op            1672 B/op         16 allocs/op
BenchmarkRSA_DecryptPKCS1v15
BenchmarkRSA_DecryptPKCS1v15-6                      1162           1026109 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptPKCS1v15SessionKey
BenchmarkRSA_DecryptPKCS1v15SessionKey-6            1149           1023830 ns/op             448 B/op          3 allocs/op
BenchmarkRSA_DecryptOAEP
BenchmarkRSA_DecryptOAEP-6                          1171           1020154 ns/op             552 B/op          8 allocs/op
BenchmarkRSA_SignPKCS1v15
BenchmarkRSA_SignPKCS1v15-6                         1140           1048296 ns/op             704 B/op          4 allocs/op
BenchmarkRSA_SignPSS
BenchmarkRSA_SignPSS-6                              1144           1051362 ns/op            1104 B/op          9 allocs/op
BenchmarkRSA_VerifyPKCS1v15
BenchmarkRSA_VerifyPKCS1v15-6                      37765             31630 ns/op            1568 B/op         11 allocs/op
BenchmarkRSA_VerifyPSS
BenchmarkRSA_VerifyPSS-6                           36705             32451 ns/op            1520 B/op         15 allocs/op

BenchmarkRSA_GenerateKeys1024
BenchmarkRSA_GenerateKeys1024-6              100          11676659 ns/op          263501 B/op       2651 allocs/op
BenchmarkRSA_GenerateKeys2048
BenchmarkRSA_GenerateKeys2048-6               52          61417782 ns/op          544929 B/op       4955 allocs/op
BenchmarkRSA_GenerateKeys4096
BenchmarkRSA_GenerateKeys4096-6                2         818490042 ns/op         2701648 B/op      14259 allocs/op

BenchmarkED25519_Sign
BenchmarkED25519_Sign-6            52149             22961 ns/op             112 B/op          2 allocs/op
BenchmarkED25519_Verify
BenchmarkED25519_Verify-6          21930             54507 ns/op              48 B/op          1 allocs/op

BenchmarkED25519_GenerateKeys-6            62968             19021 ns/op             208 B/op          4 allocs/op
```

### 🎨 贡献者

如果您觉得 cryptox 缺少您需要的功能，请不要犹豫，马上参与进来，发起一个 _**issue**_。
