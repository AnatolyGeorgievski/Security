#!/bin/sh
# RSA SHA-256: самоподпись ключа и отсоединённая подпись файла.
# Нужен системный /usr/bin/gpg только чтобы выписать ключ и подпись.
set -e
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
TOOL="$ROOT/gpg"
[ -x "$TOOL" ] || { echo "нет $TOOL, сначала make"; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
printf '%s\n' 'cert-digest-algo SHA256' 'personal-digest-preferences SHA256' > "$GNUPGHOME/gpg.conf"
/usr/bin/gpg --batch --pinentry-mode loopback --passphrase '' \
  --quick-gen-key 'r3test' rsa2048 sign never >/dev/null
printf '%s' 'payload-for-rsa' > "$WORK/doc"
/usr/bin/gpg --batch --pinentry-mode loopback --passphrase '' \
  --digest-algo SHA256 --detach-sign -o "$WORK/doc.sig" "$WORK/doc"
/usr/bin/gpg --export > "$WORK/pub.pgp"

out=$("$TOOL" --import "$WORK/pub.pgp" "$WORK/doc.sig")
printf '%s\n' "$out" | grep -c 'Сертификация пройдена!' | grep -qx 2
printf '%s\n' "$out" | grep -q 'НЕ пройдена' && exit 1

printf 'X' >> "$WORK/doc"
out=$("$TOOL" --import "$WORK/pub.pgp" "$WORK/doc.sig")
printf '%s\n' "$out" | grep -q 'Сертификация пройдена!'
printf '%s\n' "$out" | grep -q 'Сертификация НЕ пройдена!'
echo 'rsa sha256: key ok, file ok, tamper rejected'
