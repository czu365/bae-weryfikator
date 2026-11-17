#!/bin/sh
# Output contains encrypted application data plus credential hashes. Protect the directory.
set -eu
umask 077
BAE_BACKUP_DIR=${1:?Podaj katalog docelowy poza publicznym katalogiem WWW}
mkdir -p "$BAE_BACKUP_DIR"
BAE_BACKUP_PATH="$BAE_BACKUP_DIR/bae-$(date -u +%Y%m%dT%H%M%SZ).dump"
docker compose exec -T db pg_dump -U bae -d bae -Fc > "$BAE_BACKUP_PATH"
printf 'Zapisano kopię: %s\nZachowaj osobno zaszyfrowaną kopię katalogu secrets.\n' "$BAE_BACKUP_PATH"
