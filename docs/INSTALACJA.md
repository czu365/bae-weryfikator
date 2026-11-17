# Instalacja BAE Weryfikatora 0.2.1 od zera

## 1. Wymagania i katalog projektu

Wymagane środowisko obejmuje serwer Linux, Docker Engine z Compose v2, Python 3, unzip i curl. Budowanie obrazów wymaga dostępu do rejestrów pakietów i obrazów. Domyślne uruchomienie korzysta z portów TCP 80 i 443.

```bash
docker version
docker compose version
python3 --version
unzip BAE-Weryfikator-0.2.1-GitHub.zip
cd bae-weryfikator
```

## 2. Sekrety i adres aplikacji

```bash
python3 scripts/init_secrets.py
```

W pliku `.env` należy ustawić `APP_HOST` na nazwę rozwiązywaną przez klientów na adres serwera i `APP_ORIGIN` na pełny adres HTTPS. Wartość `BAE_SECRET_GID` wynika z grupy plików sekretów i jest zapisywana przez skrypt.

```dotenv
APP_HOST=bae.example.test
APP_ORIGIN=https://bae.example.test
```

Do testu lokalnego wystarcza domyślne `localhost`. Zalecana jest zaszyfrowana kopia sekretów. Baza i klucze szyfrowania są potrzebne do odtworzenia danych.

## 3. Budowa i uruchomienie usług

```bash
docker compose config --quiet
docker compose build api web
docker compose up -d
docker compose ps -a
```

Usługa `migrate` ma zakończyć pracę kodem 0. API i worker powinny działać. Diagnostyka nieudanego startu jest dostępna przez `docker compose logs --tail=100 migrate api worker web`.

## 4. HTTPS i gotowość usług

Domyślny Caddy wystawia certyfikat przy użyciu własnego CA. Test gotowości wykorzystuje publiczny certyfikat CA po potwierdzeniu jego odcisku w zaufanym kanale. Adres testu powinien odpowiadać wartości `APP_ORIGIN`.

```bash
docker compose cp web:/data/caddy/pki/authorities/local/root.crt ./bae-root-ca.crt
curl --fail --show-error --cacert ./bae-root-ca.crt https://bae.example.test/api/health/ready
```

Przeglądarka wymaga zaufania do CA Caddy lub certyfikatu od wystawcy już zaufanego przez klientów. W drugim wariancie certyfikat z łańcuchem i klucz są montowane wyłącznie do kontenera `web`. Dyrektywa `tls /ścieżka/certyfikat.pem /ścieżka/klucz.pem` zastępuje `tls internal` w `Caddyfile`. Zmiana konfiguracji wymaga ponownej budowy usługi poleceniem `docker compose up -d --build web`.

## 5. Konto administratora i MFA

```bash
docker compose exec api python -m app.cli create-admin administrator
```

Polecenie pobiera hasło interaktywnie. Aktywacja MFA odbywa się pod adresem `APP_ORIGIN` przez **Pierwsze logowanie — aktywuj MFA**. Wymagane jest dodanie konta w aplikacji TOTP i potwierdzenie kodu. Kolejne logowania wymagają hasła i aktualnego kodu TOTP.

## 6. Integracja i weryfikacja działania

1. Próba importu syntetycznego pliku CSV lub JSON w zakładce **Weryfikacja masowa** obejmuje mapowanie pól i podgląd rekordów.
2. [Konfiguracja BAE](PODLACZENIE_BAE.md) obejmuje środowisko, autoryzację i uprawnienia. Gotowość integracji potwierdza autoryzowane wyszukiwanie w środowisku testowym.
3. Po zakończeniu lub wstrzymaniu zadania akcja **Ponów wymagające kontroli** ponawia wybrane pozycje. Okno **Powód kontroli** wyświetla szczegóły wyniku.
4. [Administracja](ADMINISTRACJA.md) opisuje retencję, kopie zapasowe i odtwarzanie.

Polecenie `docker compose down` zatrzymuje zestaw. Wolumeny i lokalne sekrety są wymagane przy aktualizacji i ponownym uruchomieniu.

Administrator ma dostęp do raportowania aktywności w **Historia zadań → Sprawdzenia i eksporty**. Szczegóły opisuje [instrukcja audytu](AUDYT.md).
