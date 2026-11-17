# BAE Weryfikator

BAE Weryfikator to aplikacja webowa do pojedynczego i masowego sprawdzania adresów do e-Doręczeń (ADE) w Bazie Adresów Elektronicznych (BAE). Integracja korzysta z Search Engine API 4.0.5 i obsługuje środowiska INT oraz PROD.

## Weryfikacja adresatów

- **Sprawdzenie pojedyncze** — wyszukiwanie po imieniu, nazwisku i numerze PESEL albo po danych adresowych.
- **Sprawdzenie masowe** — import CSV (UTF-8, separator przecinek lub średnik) albo JSON (tablica obiektów), podgląd i mapowanie pól. Limit importu wynosi 100 000 wierszy lub 128 MiB. Identyfikatory i PESEL są przechowywane jako tekst.
- **Przetwarzanie w kolejce** — walidacja danych wejściowych, współdzielenie zapytania przez duplikaty w obrębie jednego zadania oraz możliwość wstrzymania, wznowienia i anulowania zadania. Redis kontroluje tempo i równoległość zapytań.
- **Analiza i eksport** — filtrowanie i korekta wierszy, historia prób, ręczne oznaczenie do kontroli oraz eksport CSV, JSON, XLSX i zbiorczego PDF. Eksport domyślnie maskuje PESEL.

## Przebieg zadania masowego

1. Import pliku i zatwierdzenie mapowania w zakładce **Weryfikacja masowa**.
2. Sprawdzenie podglądu, wykrytych duplikatów i błędów wejściowych.
3. Uruchomienie weryfikacji po skonfigurowaniu autoryzacji BAE i nadaniu uprawnień do importu.
4. Przegląd wyników oraz szczegółów w oknie **Powód kontroli**. Po zakończeniu lub wstrzymaniu zadania dostępne jest **Ponów wymagające kontroli**.
5. Eksport wybranego zakresu wyników ze wstrzymanego lub zakończonego zadania.

**Brak dopasowania** oznacza brak wyniku dla użytych kryteriów. Niejednoznaczności i ostrzeżenia trafiają do kontroli. Błędy techniczne i odmowy dostępu mają odrębne statusy.

## Architektura i dostęp

Caddy udostępnia interfejs React przez HTTPS i przekazuje ruch do API FastAPI. PostgreSQL przechowuje zadania, wyniki i audyt. Osobny worker wykonuje zapytania do BAE. Dane osobowe i wyniki są szyfrowane kluczami przechowywanymi poza bazą.

Aplikacja obsługuje konta lokalne oraz LDAPS. Dostęp kontrolują role administratora, operatora i audytora oraz obowiązkowe MFA TOTP.

## Instalacja i dokumentacja

Do uruchomienia wymagane są Linux, Docker Engine z Compose v2 i Python 3. Zapytania do BAE wymagają autoryzowanego dostępu do wybranego środowiska.

| Dokument | Zakres |
|---|---|
| [Instalacja](docs/INSTALACJA.md) | Konfiguracja, HTTPS, uruchomienie i pierwsze logowanie |
| [Integracja z BAE](docs/PODLACZENIE_BAE.md) | INT i PROD, certyfikaty i autoryzacja |
| [Administracja](docs/ADMINISTRACJA.md) | Konta, retencja, monitoring i kopie zapasowe |
| [Architektura](docs/ARCHITEKTURA.md) | Komponenty, przepływ danych i statusy |
| [Testy](docs/TESTY.md) | Testy lokalne i profil PostgreSQL |
| [Publikacja na GitHubie](docs/PUBLIKACJA_GITHUB.md) | Repozytorium, tag i wydanie |

## Audyt sprawdzeń i eksportów

Widok **Historia zadań → Sprawdzenia i eksporty** pozwala administratorowi odczytać login operatora, kryteria prób wyszukiwania i zawartość wygenerowanych plików. Raport CSV obejmuje wszystkie operacje w wybranym okresie i jest dostępny w tym samym widoku. Zakres danych i retencję opisuje [instrukcja audytu](docs/AUDYT.md). Procedura dla działającego wdrożenia znajduje się w [instrukcji aktualizacji](docs/AKTUALIZACJA.md).

## Firewall/UTM ##

Na firewallu/UTM można zostawić tylko HTTPS resztę można zablokować
