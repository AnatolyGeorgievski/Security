# Security — песочница Ring-3

> ::TAGS:: класс, canon, зерно, проверка, gpg, hmac, пазл

> ::TOC::
> - [Чтение](#чтение)
> - [Лицензия](#лицензия)

## Чтение

Алгоритм проверяется здесь и входит в [R3-lib](https://github.com/AnatolyGeorgievski/R3-lib/blob/main/README.md) уже принятым файлом. Норматив экосистемы — [Ring-3](https://github.com/AnatolyGeorgievski/godminer/blob/main/docs/R3_README.md).

| метка | документ |
|---|---|
| класс, мост, canon | [разворот из зерна](log/2026-10-14%20%D1%80%D0%B0%D0%B7%D0%B2%D0%BE%D1%80%D0%BE%D1%82%20%D0%B8%D0%B7%20%D0%B7%D0%B5%D1%80%D0%BD%D0%B0.md#форма-разворота) |
| пазл, фрактал, наблюдатель | [модели мышления](log/2026-10-14%20%D0%BC%D0%BE%D0%B4%D0%B5%D0%BB%D0%B8%20%D0%BC%D1%8B%D1%88%D0%BB%D0%B5%D0%BD%D0%B8%D1%8F.md) |
| throughput | [принципы оптимизации](log/2026-10-14%20%D0%BF%D1%80%D0%B8%D0%BD%D1%86%D0%B8%D0%BF%D1%8B%20%D0%BE%D0%BF%D1%82%D0%B8%D0%BC%D0%B8%D0%B7%D0%B0%D1%86%D0%B8%D0%B8.md) |
| квант, остаток | [журнал QuantumNN](https://github.com/AnatolyGeorgievski/QuantumNN/blob/main/log/2026-10-15.md) |
| prng | [журнал MWC128](https://github.com/AnatolyGeorgievski/MWC128/blob/main/log/2026-10-15.md) |
| herd, react | [фрактальная карта e9pro](https://github.com/AnatolyGeorgievski/godminer/blob/main/log/2026-10-14%20%D1%84%D1%80%D0%B0%D0%BA%D1%82%D0%B0%D0%BB%D1%8C%D0%BD%D0%B0%D1%8F%20%D0%BA%D0%B0%D1%80%D1%82%D0%B0%20e9pro.md#следующая-стыковка) |

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

## Лицензия

MIT, как у R3-net и R3-build. Текст — файл `LICENSE`, copyright AnatolyGeorgievski.

Песочница кормит разные проекты и с ними не сливается. MIT позволяет перенести файл и в GPL-библиотеку `R3-lib`, и в MIT-деревья. У `R3-lib` лицензия остаётся своей: туда попадает уже принятый алгоритм, не весь репозиторий.
