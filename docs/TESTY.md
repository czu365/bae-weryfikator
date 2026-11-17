# Testy aplikacji

## Zakres testów automatycznych

- PESEL: suma kontrolna, rzeczywista data urodzenia, zachowanie polskich liter.
- UTF-8 z BOM/bez BOM, oba separatory CSV, zera początkowe, różne nagłówki i zagnieżdżony adres JSON.
- Błędne kodowanie, nieprawidłowa struktura, powtórzone nagłówki, zła liczba kolumn, nieobsługiwane formaty i atomowe wycofanie importu.
- Deduplikacja bez utraty osobnych ID i kolejności, ponowne mapowanie szkicu.
- Weryfikacja budowy żądań i odpowiedzi na dołączonym oficjalnym kontrakcie 4.0.5.
- Mock HTTP: 401, 403, 400, 429, 503, przekierowanie, awaria sieci; brak zamiany błędu na brak dopasowania.
- Niejednoznaczność, rozbieżność danych, ostrzeżenie dostawcy i nieaktywny/nieujawniony ADE.
- Podpis JWT RSA, wymagane claims, format client credentials i współdzielenie zaszyfrowanego tokenu bez kolejnego pobrania przed wygaśnięciem.
- Izolacja zadań operatorów, uprawnienia audytora, blokada administracji i pełnego PESEL.
- Aktywacja TOTP, logowanie MFA, blokada ponownego użycia kodu, CSRF, odrzucenie obcego Origin i brak odbicia wrażliwego wejścia w komunikacie walidacji.
- Wznowienie po wygaśnięciu dzierżawy, pauza/anulowanie, Retry-After, blokada przy odmowie uprawnień, historia kolejnych prób oraz ponawianie wyłącznie zaznaczonych.
- CSV/JSON/XLSX/PDF, maskowanie PESEL, zachowanie ID per wiersz, ręczna kontrola i neutralizacja formuł arkusza.

W testach występują jawnie syntetyczne adaptery i tokeny. Nie są one dostępne jako tryb uruchomieniowy aplikacji. Izolowany adapter użyty do wizualnego sprawdzenia UI nie znajduje się w paczce.

## Uruchomienie lokalne

Z katalogu projektu po instalacji `backend/requirements-test.txt`:

```bash
pytest -q backend/tests
BAE_LOAD_TEST=1 BAE_LOAD_UNIQUE=1000 pytest -q -s backend/tests/test_load.py
BAE_LOAD_TEST=1 BAE_LOAD_UNIQUE=100000 pytest -q -s backend/tests/test_load.py
npm --prefix frontend ci
npm --prefix frontend run build
```

Ostrzeżenie biblioteki Starlette o planowanej zmianie klienta testowego httpx nie jest błędem testów. Kod aplikacji używa httpx do połączenia SE API; testowy klient HTTP jest odrębny.

## PostgreSQL i Docker

Profil `test` uruchamia odizolowaną bazę `bae_test` w tmpfs. Wolumen produkcyjny `pgdata` pozostaje poza profilem testowym.

```bash
python3 scripts/init_secrets.py
docker compose --profile test build test
docker compose --profile test run --rm test
docker compose --profile test run --rm -e BAE_LOAD_TEST=1 -e BAE_LOAD_UNIQUE=100000 test pytest -q -s tests/test_load.py
```

Można wskazać zewnętrzną, wyłącznie testową bazę przez `BAE_TEST_DATABASE_URL`. Nazwa bazy musi zaczynać się od `bae_test`. **Testy usuwają i tworzą swoje tabele przy każdym przypadku; nigdy nie kieruj ich do używanej bazy urzędu.** Hasło może być dostarczone przez `DB_PASSWORD_FILE`.

Przed odbiorem potrzebny jest dodatkowy test kilku workerów z rzeczywistym PostgreSQL/Redis, równoczesną pauzą i ponowieniami, wymuszoną awarią procesu oraz odtworzeniem kopii. Lokalne SQLite nie dowodzi poprawności blokad PostgreSQL przy dużej współbieżności.
