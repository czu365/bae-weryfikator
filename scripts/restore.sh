#!/bin/sh
# Restores into an EMPTY database; refuses overwrite. Restore secret keys first.
set -eu
BAE_DUMP_FILE=${1:?Podaj plik kopii pg_dump}
BAE_TABLE_COUNT=$(docker compose exec -T db psql -U bae -d bae -Atc "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")
if [ "$BAE_TABLE_COUNT" != 0 ]; then
  printf 'Baza nie jest pusta. Odtwarzaj na osobnej instancji; istniejąca baza pozostaje bez zmian.\n' >&2
  exit 1
fi
docker compose exec -T db pg_restore -U bae -d bae --no-owner --exit-on-error < "$BAE_DUMP_FILE"
printf 'Odtworzono bazę. Zweryfikuj zgodność kluczy szyfrowania przed uruchomieniem aplikacji.\n'
