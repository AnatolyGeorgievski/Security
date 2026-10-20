# ChangeLog

<tags>журнал, сборка, хеш</tags>

<toc>
- [2026-10-14](#2026-10-14)
- [2026-10-13](#2026-10-13)
- [Сверка SHA-1](#сверка-sha-1)
- [Сверка SHAKE256](#сверка-shake256)
</toc>

Формат близок к Keep a Changelog. Даты — день работы, не semver.

## [2026-10-14]

### Added
- `src/pkix/`: просмотр PEM, CMS и контейнеров PKCS. `Makefile` собирает OCSP из `src/bigbrother/ocsp` на месте. Каталог bigbrother, сертификаты и закрытый ключ в коммит не входят. Загрузка издателя и CRL по HTTP — заглушка `http_rest`. Кривые и разбор OCSP — заглушки `eckey_stub.c` и `ocsp_stub.c`: в дереве нет `mp.h`.
- Кузнечик регистрируется в `cipher` из `kuzn_clmul.c` (PCLMUL и не GFNI), `kuzn_gfni.c` и `kuzn_neon.c`. Собственный `main` закрыт `TEST_KUZN` и `TEST_KUZN_CLMUL`.
- `cpuid` держит AVX2 отдельным флагом и печатает его рядом с AVX-VNNI, AVX-IFMA, AVX-VNNI-INT8, AVX-NE-CONVERT и AVX-VNNI-INT16. Имена AVX512-IFMA, AVX512-VBMI, AVX512-VNNI и AVX512-BF16. Добавлены MOVRS и AMX-COMPLEX.

### Changed
- `src/magma.c`: CRISP переведён на `CRISP_t`. Появились `crisp_key_id`, дерево KDF, `crisp_set_key`, `crisp_encode` и `crisp_decode` с окном номеров. Прежний контур MGM снят.
- В комментарии AES: «развернутого ключа».

### Журнал
- `log/2026-10-14 Заново изобретаем простые числа.md`: порядок группы L = 2^252 + D и тот же каркас редукции, что для поля 2^255-19.
- `log/2026-10-14 модели мышления.md`: отзыв про резонансный контур и проверка речевого буфера снаружи ответа.
- `log/2026-10-14 разворот из зерна.md`: таблица класса BN. Модульные `mp_addm` и соседи в класс не входят.

## [2026-10-13]

### Added
- В `gpg` добавлены `src/sha512.c` (SHA-384, SHA-512, SHA-512/224, SHA-512/256) и `src/md5.c` (MD5). SHA-256 по-прежнему тянется из R3-lib (`-Wl,-u,sha256`). SM3 не подключён: регистрация в `src/sm3.c` стоит под `#if 0`.
- Сборка `cksum` по списку `src/Makefile-cksum`: `cksum.c`, `crc16_clmul.c`, `r3_args.c`, заголовок `src/crc.h`.
- `src/blake2b.c` и `src/blake2s.c` — копии файлов, не симлинки. `src/ecc.h` и `src/crc.h` переведены в UTF-8.

- `Makefile`: сборка `gpg` теми же ключами, что `godminer/src/netd_minimal.mak` (`-O3`, `-march=native` либо armv7/aarch64, `-ffast-math`, `-ftree-vectorize`, `-fPIC`, `-DGnuPG`).
- `src/gpg_build.h`, `src/rsa.h`, `src/segment.h`.
- `src/blake2b.c`, `src/blake2s.c` — ссылки на `R3-lib`, чтобы `#include "hmac.h"` был заголовком Security.
- `test/test_gpg_rsa.sh`: RSA 2048, SHA-256, самоподпись ключа и отсоединённая подпись; порча файла отвергается.
- Журнал сборки: `log/2026-10-13 сборка gpg.md`.
- `src/sha1.c` — SHA-1 из `godminer/test/sha1.c`. `README.md`: песочница криптоалгоритмов.

### Fixed
- `pgp_parse`: пустой `digest_select` больше не читает `md->hash_len`. Печатается `hash alg N не собран`.
- `rsa_public_key_free`: модуль берётся через `memalign`, не через `mmap` из `libr3`.
- `pkcs_encode`: метка SHA3-256 — `hash_tag_sha3_256`.
- `Add512` / `UADD`: аргумент `_addcarry_u64` приведён к `unsigned long long *` (GCC 14).
- Конструктор GOST R 34.11-94 не печатает `Init paramset` при старте.

### Changed
- `src/shake256.c` заменён реализацией из `godminer/src/shake256.c` (тот же файл, что `R3-lib/src/shake256.c`). `Makefile` собирает `src/shake256.c`.
- В `MDigest` добавлено поле `digest` в конец структуры. Его задают регистраторы SHA3.

## Сверка SHA-1

Копия `godminer/test/sha1.c` лежит в `src/sha1.c`. Отдельной реализации в Security до этого не было: комментарии называли `sha.c`, файла не было. `Makefile` собирает `src/sha1.c`. Перед локальной `htole32` стоит `#undef htole32`.

## Сверка SHAKE256

`R3-lib/src/shake256.c` и `godminer/src/shake256.c` совпадают побайтно (1100 строк). Старый `Security/src/shake256.c` был 610 строк и в сборку `gpg` не входил.

Общее у обоих: χ, θ, π, ρ на векторах 5×64, `KeccakF1600`, домен `0x1F` для SHAKE и `0x06` для SHA3, скорости 168/136/144/104/72.

В godminer сверх старого файла Security:

- потоковый `sha3_update` / `sha3_final` для SHA3-224, SHA3-256, SHA3-384 и SHA3-512, регистрация `MESSAGE_DIGEST` включена;
- `keccak_256` / `keccak_384` / `keccak_512` (домен `0x01`);
- `cshake256`, `XOF_init` / `XOF_absorb` / `XOF_squeeze`;
- `KeccakF800`;
- `main` только под `-DTEST_SHA3`.

В старом файле Security `sha3_256_update` пустой, блок регистрации закрыт `#if 0`, `main` собирался всегда. Поэтому в дерево Security положена реализация godminer.
