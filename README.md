# ð Cryptox

[![Go Doc](_icons/godoc.svg)](https://pkg.go.dev/github.com/FishGoddess/cryptox)
[![License](_icons/license.svg)](https://opensource.org/licenses/MIT)
[![Coverage](_icons/coverage.svg)](_icons/coverage.svg)
![Test](https://github.com/FishGoddess/cryptox/actions/workflows/test.yml/badge.svg)

**Cryptox** æ¯ä½¿ç¨ Go å¼åçå®å¨å¥ä»¶ï¼åæ¬äºå¸¸ç¨çå¯¹ç§°å å¯åéå¯¹ç§°å å¯ç®æ³ï¼è¿ææ£åç®æ³ãç¼è§£ç å¸¸ç¨ç®æ³ç­ï¼ä¸»è¦æ¯ä¸ºäºæ¹ä¾¿ç¸å³åºæ¯ä½¿ç¨ã

[Read me in English](./README.en.md)

### ð¡ åè½ç¹æ§

* æ¯æ DES/3DES/AES ç­å¯¹ç§°å å¯ç®æ³ã
* æ¯æ RSA/ECC ç­éå¯¹ç§°å å¯ç®æ³ã
* æ¯æ ECB/CBC/OFB/CFB/CTR ç­åç»æ¨¡å¼ã
* æ¯æ PKCS5/PKCS7/ZERO/NO ç­å¡«åæ¹å¼ã
* æ¯æ MD5/SHA1/SHA256/SHA512/HMAC ç­æ£åç®æ³ã
* æ¯æ CRC/FNV ç­æ£åç®æ³ã
* æ¯æ HEX/BASE64 ç­ç¼è§£ç ç®æ³ã

_åå²çæ¬çç¹æ§è¯·æ¥ç [HISTORY.md](./HISTORY.md)ãæªæ¥çæ¬çæ°ç¹æ§åè®¡åè¯·æ¥ç [FUTURE.md](./FUTURE.md)ã_

### â ä½¿ç¨æ¹å¼

```shell
$ go get -u github.com/FishGoddess/cryptox
```

* [des](_examples/des.go)
* [triple_des](_examples/triple_des.go)
* [aes](_examples/aes.go)
* [hash](_examples/hash.go)
* [rsa_key](_examples/rsa_key.go)
* [rsa](_examples/rsa.go)

### ð´ð» æ§è½æµè¯

```shell
$ go test -v -bench=. -benchtime=1s _examples/*_test.go
```

_æ³¨ï¼æ°æ®ä¸º 128 å­èï¼ecb/cbc ä¸º pkcs7 å¡«åï¼cfb/ofb/ctr ä¸ºä¸å¡«åã_

```
goos: darwin
goarch: amd64
cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz

BenchmarkAESEncryptWithECB-12            2376924               506 ns/op             960 B/op          6 allocs/op
BenchmarkAESEncryptWithCBC-12            1704799               699 ns/op            1072 B/op          9 allocs/op
BenchmarkAESEncryptWithCFB-12            1890339               632 ns/op             816 B/op          8 allocs/op
BenchmarkAESEncryptWithOFB-12            1000000              1029 ns/op            1312 B/op          8 allocs/op
BenchmarkAESEncryptWithCTR-12             979789              1186 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptWithECB-12            2811610               429 ns/op             720 B/op          5 allocs/op
BenchmarkAESDecryptWithCBC-12            2013831               613 ns/op             832 B/op          8 allocs/op
BenchmarkAESDecryptWithCFB-12            1935090               625 ns/op             816 B/op          8 allocs/op
BenchmarkAESDecryptWithOFB-12            1000000              1025 ns/op            1312 B/op          8 allocs/op
BenchmarkAESDecryptWithCTR-12            1000000              1173 ns/op            1312 B/op          8 allocs/op
BenchmarkDESEncryptWithECB-12             351558              3444 ns/op             512 B/op          3 allocs/op
BenchmarkDESEncryptWithCBC-12             334164              3668 ns/op             608 B/op          6 allocs/op
BenchmarkDESEncryptWithCFB-12             352360              3566 ns/op             352 B/op          5 allocs/op
BenchmarkDESEncryptWithOFB-12             148867              8146 ns/op             856 B/op          5 allocs/op
BenchmarkDESEncryptWithCTR-12             138829              8547 ns/op             856 B/op          5 allocs/op
BenchmarkDESDecryptWithECB-12             356511              3427 ns/op             272 B/op          2 allocs/op
BenchmarkDESDecryptWithCBC-12             327507              3664 ns/op             368 B/op          5 allocs/op
BenchmarkDESDecryptWithCFB-12             345454              3552 ns/op             352 B/op          5 allocs/op
BenchmarkDESDecryptWithOFB-12             145267              8183 ns/op             856 B/op          5 allocs/op
BenchmarkDESDecryptWithCTR-12             144640              8451 ns/op             856 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithECB-12       131902              9259 ns/op             768 B/op          3 allocs/op
BenchmarkTripleDESEncryptWithCBC-12       126849              9468 ns/op             864 B/op          6 allocs/op
BenchmarkTripleDESEncryptWithCFB-12       130987              9276 ns/op             608 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithOFB-12        57150             20805 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESEncryptWithCTR-12        55443             21344 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithECB-12       132991              9236 ns/op             528 B/op          2 allocs/op
BenchmarkTripleDESDecryptWithCBC-12       117877              9483 ns/op             624 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithCFB-12       129415              9064 ns/op             608 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithOFB-12        56397             20979 ns/op            1112 B/op          5 allocs/op
BenchmarkTripleDESDecryptWithCTR-12        56103             21694 ns/op            1112 B/op          5 allocs/op

BenchmarkMD5-12                  7447408               156.3 ns/op           112 B/op          2 allocs/op
BenchmarkSHA1-12                 6629499               184.2 ns/op           136 B/op          2 allocs/op
BenchmarkSHA224-12               4768708               249.6 ns/op           160 B/op          2 allocs/op
BenchmarkSHA256-12               4755806               256.2 ns/op           160 B/op          2 allocs/op
BenchmarkSHA384-12               3717706               329.8 ns/op           272 B/op          2 allocs/op
BenchmarkSHA512-12               3679125               325.5 ns/op           288 B/op          2 allocs/op
BenchmarkHMAC-12                 1215033               988.4 ns/op           512 B/op          6 allocs/op
BenchmarkCRC32IEEE-12           17037747                70.4 ns/op            24 B/op          2 allocs/op
BenchmarkCRC64ISO-12            26904604                44.8 ns/op             8 B/op          1 allocs/op
BenchmarkCRC64ECMA-12           26632101                44.4 ns/op             8 B/op          1 allocs/op
BenchmarkFnv32-12               41738200                28.2 ns/op             8 B/op          1 allocs/op
BenchmarkFnv32a-12              42062208                29.0 ns/op             8 B/op          1 allocs/op
BenchmarkFnv64-12               39065052                29.9 ns/op             8 B/op          1 allocs/op
BenchmarkFnv64a-12              39740802                29.9 ns/op             8 B/op          1 allocs/op
BenchmarkFnv128-12              23474830                50.2 ns/op            16 B/op          1 allocs/op
BenchmarkFnv128a-12             24201123                50.3 ns/op            16 B/op          1 allocs/op

BenchmarkRSAEncryptPKCS1v15-12                     23575             51665 ns/op            5119 B/op         12 allocs/op
BenchmarkRSAEncryptOAEP-12                         23125             54832 ns/op            5475 B/op         18 allocs/op
BenchmarkRSADecryptPKCS1v15-12                       806           1388847 ns/op           26180 B/op        102 allocs/op
BenchmarkRSADecryptPKCS1v15SessionKey-12             856           1367107 ns/op           26179 B/op        102 allocs/op
BenchmarkRSADecryptOAEP-12                           812           1377677 ns/op           26284 B/op        107 allocs/op
```

### ð¨ è´¡ç®è

å¦ææ¨è§å¾ cryptox ç¼ºå°æ¨éè¦çåè½ï¼è¯·ä¸è¦ç¹è±«ï¼é©¬ä¸åä¸è¿æ¥ï¼åèµ·ä¸ä¸ª _**issue**_ã

### ðª ä½¿ç¨ cryptox çé¡¹ç®

| é¡¹ç®  | ä½è  | æè¿°  | é¾æ¥                  |
|-----|-----|-----|---------------------|
|     |     |     | [Github]() / [ç äº]() |

æåï¼ææ³æè°¢ JetBrains å¬å¸ç **free JetBrains Open Source license(s)**ï¼å ä¸º cryptox æ¯ç¨è¯¥è®¡åä¸ç Idea / GoLand å®æå¼åçã

<a href="https://www.jetbrains.com/?from=cryptox" target="_blank"><img src="./_icons/jetbrains.png" width="250"/></a>