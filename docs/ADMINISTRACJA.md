# Administracja i utrzymanie

## Usługi

| Usługa | Zadanie | Port hosta |
|---|---|---|
| web | Caddy, interfejs, TLS, proxy | 443, przekierowanie z 80 |
| api | FastAPI, autoryzacja, import i eksport | brak |
| worker | Trwała kolejka wyszukiwań | brak |
| migrate | Jednorazowe migracje przy starcie | brak |
| db | PostgreSQL 17 | brak |
| redis | Tokeny, limity, blokady, heartbeat | brak |

Sugerowany punkt wyjścia dla testów 100 000 rekordów: 4 vCPU, 8 GB RAM, SSD i odpowiedni zapas miejsca na zaszyfrowane dane oraz historię prób. To oszacowanie wdrożeniowe, nie wynik obciążenia całego zestawu kontenerów. Dane bazy są w `pgdata`, konfiguracja CA Caddy w `caddydata` i `caddyconfig`.

## HTTPS w LAN

Domyślne `tls internal` tworzy CA wewnętrzne Caddy. Administrator może wyeksportować jego publiczny certyfikat:

```bash
docker compose cp web:/data/caddy/pki/authorities/local/root.crt ./bae-root-ca.crt
```

Dystrybucja publicznego certyfikatu CA przez zarządzany magazyn zaufania wymaga wcześniejszego potwierdzenia odcisku. Certyfikat musi być zaufany także na urządzeniach testujących. Wariant z własnym CA wykorzystuje certyfikat i klucz zamontowane wyłącznie w Caddy oraz wskazane w dyrektywie `tls`. Walidacja TLS obowiązuje po stronie klienta i adaptera BAE.

`APP_ORIGIN` to pełne pochodzenie, np. `https://bae.example.test`, bez ścieżki. `APP_HOST` to sama nazwa hosta. Nazwa hosta wymaga rekordu DNS wskazującego serwer. Dostęp do panelu podlega kontroli sieciowej. PostgreSQL i Redis nie są publikowane na hoście.

## Sekrety

`init_secrets.py` tworzy wyłącznie brakujące pliki. Nie nadpisuje kluczy i haseł. Wszystkie powinny mieć tryb `640`, a katalog `750`, z grupą odpowiadającą `BAE_SECRET_GID`. Proces aplikacji ma UID 10001 i dodatkową wskazaną grupę. Certyfikaty i klucze BAE dodaj z tymi samymi prawami. Nie zapisuj ich w repozytorium, pliku CSV ani panelu w postaci tekstowej.

Zaszyfrowana kopia `secrets/` powinna być przechowywana oddzielnie od kopii bazy. Szyfrowanie kolumn nie chroni przed uprawnionym procesem uruchomionym na przejętym serwerze. Urzędowy magazyn sekretów lub HSM może zastąpić magazyn plikowy po dostosowaniu dostawcy kluczy; integracji z HSM nie zaimplementowano.

`data_key` szyfruje dane i wyniki, `index_key` służy do HMAC i sesji. Zmiana `index_key` wymaga migracji indeksów i unieważnia dotychczasowe sesje. Rotacja `data_key` wymaga kontrolowanego ponownego szyfrowania wszystkich kolumn i sekretów. Nie ma przycisku automatycznej rotacji. Aktualizacja wymaga zachowania istniejących kluczy.

PostgreSQL zawiera również hashe haseł i metadane administracyjne. Wymagane pełne szyfrowanie dysków/backupów obejmij mechanizmami infrastruktury urzędu. Usuwanie danych według retencji nie usuwa ich z wcześniejszych kopii zapasowych — kopie muszą mieć osobny harmonogram rotacji.

## Konta, role, MFA

Administrator zakłada konta lokalne lub mapuje istniejący login domenowy. Operator widzi i zmienia własne zadania; administrator widzi wszystkie; audytor ma odczyt danych i raportów, bez korekt, importów, konfiguracji i pełnego PESEL. Ujawnienie pełnego PESEL przy edycji lub eksporcie jest audytowane.

Użytkownik sam aktywuje TOTP po potwierdzeniu hasła. Po aktywacji wymagane jest hasło i kod TOTP. Ten sam kod czasowy nie może zostać ponownie wykorzystany do logowania. Konta są ograniczane próbami na kombinację loginu i adresu źródłowego, sam login i samo źródło. Redis musi działać — jego awaria blokuje logowanie, zamiast wyłączać ochronę.

Reset po weryfikacji tożsamości użytkownika:

```bash
docker compose exec api python -m app.cli reset-password login
docker compose exec api python -m app.cli reset-mfa login
```

Obie operacje unieważniają dotychczasowe sesje użytkownika. Nie ma odzyskiwania hasła e-mailem ani publicznej rejestracji. Administrator nie zmienia roli ani aktywności własnego konta przez panel. Hasła nie trafiają do argumentów poleceń.

## Active Directory / LDAPS

Przykładowa konfiguracja LDAPS w `.env`:

```dotenv
LDAP_HOST=ldap.example.test
LDAP_DOMAIN=example.test
LDAP_CA_FILE=/run/bae/ad-ca.pem
```

Konfiguracja wymaga zaufanego certyfikatu CA w `secrets/ad-ca.pem`, odtworzenia kontenerów API, workera i migracji oraz konta typu `ldap` z przypisaną rolą. Logowanie wykonuje bind przez LDAPS na porcie 636 jako `login@LDAP_DOMAIN`, z walidacją certyfikatu. Brak automatycznego nadawania ról według grup AD i brak dostępu dla dowolnego użytkownika domeny. Hasło AD jest używane tylko do bind i nie jest zapisywane. TOTP nadal obowiązuje.

Ten adapter musi zostać przetestowany z rzeczywistym AD przed uruchomieniem domenowych kont produkcyjnych. SSO/Kerberos, Entra/OIDC i mapowania grup nie zostały zaimplementowane.

## Kolejka i restart

Zadania i rekordy oczekujące pozostają w PostgreSQL. Redis nie jest źródłem kolejki. Worker rezerwuje zapytanie na 180 s; po awarii procesu inny worker może przejąć wygasłą dzierżawę. Wynik jest zapisany tylko przez proces posiadający nadal właściwy token dzierżawy. Retry jest maksymalnie pięciopróbny; po wyczerpaniu prób pozostaje błąd techniczny.

Możliwe jest powtórzenie zapytania po awarii dokładnie między odpowiedzią BAE a zapisem w bazie. Kolejka stosuje semantykę przetwarzania co najmniej raz. Wyszukiwanie nie wysyła korespondencji i nie zmienia danych BAE.

Pauza i anulowanie zatrzymują dalsze zapytania. Zapytanie już wysłane może zakończyć się i zapisać wynik. Nie przerywa się połączenia w połowie, żeby stworzyć pozór niewykonanego sprawdzenia. Rekordy oczekujące nie są zamieniane na brak dopasowania. Zmiana danych wymaga zatrzymania kolejki. Ponawianie duplikatu dotyczy wspólnego zapytania i jego powiązanych wierszy.

Domyślnie jeden worker. W razie uzgodnionej z dostawcą potrzeby można skalować procesy, ale panelowe limity globalnego tempa i równoległości nadal obowiązują:

```bash
docker compose up -d --scale worker=2
```

Blokady slotów Redis wygasają. Liczba procesów zależy od zatwierdzonej konfiguracji i możliwości bazy. Po zmianie środowiska wstrzymane zadania z poprzedniego środowiska nie mogą być wznawiane przeciwko innemu środowisku.

## Retencja i pliki
 Szczegóły sprawdzeń i eksportów podlegają retencji audytu. Dostęp oraz zawartość raportu opisuje [instrukcja audytu](AUDYT.md).

Domyślnie dane zadań są przechowywane 30 dni, audyt 365 dni. Administrator zmienia te wartości w panelu. Worker co godzinę usuwa wygasłe, nieaktywne zadania, ich rekordy, zapytania i próby; aktywne zadania nie są kasowane w trakcie pracy. Retencja zadań jest liczona od daty utworzenia.

Uploady są parsowane w ograniczonym pliku tymczasowym i usuwane po zakończeniu żądania. `/tmp` w kontenerze jest tmpfs, więc dane z uploadu lub biblioteki XLSX nie są trwale odkładane na zwykły dysk. Katalog tymczasowy wymaga kontrolowanego magazynu nietrwałego. Limity są sprawdzane przez proxy oraz backend.

## Monitoring

- `/api/health/live` — działa proces API.
- `/api/health/ready` — działają DB, Redis i świeży heartbeat co najmniej jednego workera. Nie oznacza autoryzacji do BAE.
- Stan certyfikatów i brakujące dane — panel Administracja.
- Logi nie zawierają treści zapytań, PESEL ani tokenów. Log dostępu Uvicorn jest wyłączony. Konfiguracja proxy powinna pomijać treści żądań i parametry wyszukiwania.

```bash
docker compose ps
docker compose logs --tail=100 api worker migrate
```

Zgłoszenia serwisowe powinny zawierać wyłącznie zanonimizowaną diagnostykę.

## Kopia i odtwarzanie

```bash
./scripts/backup.sh /bezpieczny/katalog/kopii
```

Skrypt wykonuje spójny `pg_dump -Fc`. Kopia wymaga szyfrowania i przeniesienia zgodnie z polityką organizacji. Klucze szyfrowania wymagają osobnego magazynu. Caddy CA i certyfikaty również wymagają zabezpieczonej kopii albo odtworzenia zgodnie z procedurą CA.

Odtwarzanie rozpoczyna się na **osobnej instancji** z pustą bazą i prawidłowymi sekretami:

```bash
docker compose up -d db
./scripts/restore.sh /bezpieczny/katalog/kopii/bae-DATA.dump
docker compose up -d
```

Skrypt odmawia nadpisania bazy zawierającej tabele. Migracje następują po odtworzeniu kopii do pustej bazy. Wznowienie zapytań wymaga sprawdzenia środowiska, certyfikatów, odszyfrowania danych i stanu zadań. Test odtworzenia w urzędowej infrastrukturze pozostaje elementem odbioru.
