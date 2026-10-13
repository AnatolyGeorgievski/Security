# Security — песочница Ring-3

Место, где пишутся и проверяются криптографические алгоритмы до того, как они входят в `R3-lib`. Свой код, без OpenSSL и libgcrypt. Сборка — обычный Linux, ключи те же, что у godminer: `-O3`, `-march=native` (armv7 / aarch64 — свои `-march`), `-ffast-math`, `-ftree-vectorize`, `-fPIC`.

Рядом лежит `R3-lib`: оттуда берётся `libr3` (`glib`-совместимые списки, `digest_select`, SHA-256). Каталог:

```
/home/{name}/Security
/home/{name}/R3-lib
```

```sh
make -C ../R3-lib
make
test/test_gpg_rsa.sh
```

`make` собирает утилиту `gpg`: разбор пакетов OpenPGP, снятие ASCII-armor (CRC-24) и проверка подписи RSA. Подпись утилита не создаёт. DSA, ECDSA и EdDSA разбираются, криптопроверка для них не включена.

Хеши, которые эта сборка регистрирует в `digest_select`: SHA-1, SHA-256, SHA3-224/256/384/512, Streebog-256/512, GOST R 34.11-94, BLAKE2s, BLAKE2b. SHA-2-512 в дереве нет. SM3 лежит в `src/sm3.c`, регистрация пока выключена.

```
src
├── hash      sha1, shake256 (SHA3, SHAKE, cSHAKE), stribog, gosthash, sm3, ghash, poly1305
├── cipher    aes, chacha20, salsa20, kuznechik, magma, belt, sm4, gost28147, crisp
├── pubkey    rsa, ecc (montgomery, edwards), ml_kem, sign
├── openpgp   gpg_sign, gpg_armor
└── codec     hmac, base64, crc, reed-solomon, gzip
```

Новый алгоритм — файл в `src/`, регистрация через `MESSAGE_DIGEST` или `SIGNATURE` в `hmac.h` / `sign.h`, затем строка в `Makefile`, если он нужен утилите `gpg`.
