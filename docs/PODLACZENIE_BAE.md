# Podłączenie do BAE

Stan analizy: 5 listopada 2026. Aplikacja obsługuje osoby fizyczne `INDIVIDUAL`, nie wszystkie kategorie adresatów.

## Oficjalne materiały

- [Interfejsy API](https://www.gov.pl/web/e-doreczenia/interfejsy-api) — aktualizacja strony 28.10.2026, wskazane SE API 4.0.5, 3.0.11 i 2.0.9.
- [Integracja systemów EZD](https://www.gov.pl/web/e-doreczenia/integracja-uslugi-e-doreczen-z-systemami-klasy-ezd) — zgłoszenia, instrukcje, projekt techniczny V4 i materiały PROD.
- [Projekt techniczny SE API V4](https://www.gov.pl/attachment/89fa728d-0342-41e2-85d5-de4556ff80fa) — DOCX z osadzonym ZIP zawierającym oryginalny YAML 4.0.5 dołączony do projektu.
- [Instrukcja INT 1.9.7](https://www.gov.pl/attachment/b0bbf5ef-8909-43ff-851d-d1183e96d02a).
- [Instrukcja PROD 1.9](https://www.gov.pl/attachment/d48d0188-cc7a-42c2-8497-99da442ef9ce).
- [Aktualna dokumentacja INT](https://int.edoreczenia.gov.pl/dokumentacja) — dostęp ograniczony do uprawnionych podmiotów.

Adapter korzysta z publicznego kontraktu 4.0.5. Przed wdrożeniem wymagane jest porównanie z kontraktem dostępnym w dokumentacji INT.

## Dostęp urzędu

1. Określ z COI właściwą ścieżkę integracji dla samodzielnego systemu dziedzinowego weryfikującego BAE i zakres uprawnień podmiotu publicznego. Aplikacja nie nadaje sobie prawa do odpytywania rejestru.
2. Dla INT zapoznaj się z regulaminem, instrukcją i formularzem zgłoszenia na oficjalnej stronie. Zgłoszenie integratora według tej strony kieruje się na `test.edoreczenia@cyfra.gov.pl`. Instrukcja wymaga wskazania publicznych adresów IP do dopuszczenia ruchu. Samo posiadanie skrzynki produkcyjnej nie daje dostępu do INT.
3. Uzyskaj testowe konta i ADE oraz dostęp do dokumentacji. Administrator lub właściciel skrzynki dodaje nowy system w module uprawnień. System przygotowuje parę kluczy i CSR; administrator rejestruje CSR i otrzymuje certyfikat zgodnie z instrukcją operatora.
4. Potwierdź dokładną nazwę systemu, ADE, uprawnienia do wyszukiwania osób, format `login_hint`, `audience` oraz przyznane limity i dozwoloną równoległość.
5. W PROD zarejestruj osobny system i osobne dane dostępowe zgodnie z instrukcją PROD. Nie kopiuj uprawnień, kluczy ani wyników testowych do produkcji.

Nie wysyłano żadnego zgłoszenia, wiadomości ani wniosku w imieniu urzędu.

## Certyfikat i klucz

Na serwerze umieść osobne pliki PEM:

| Środowisko | Certyfikat | Klucz prywatny |
|---|---|---|
| INT | `secrets/int.crt` | `secrets/int.key` |
| PROD | `secrets/prod.crt` | `secrets/prod.key` |

Klucz RSA co najmniej 2048 bitów, nieszyfrowany PEM w zabezpieczonym magazynie plikowym; para musi pasować i certyfikat musi być ważny. Dostęp wyłącznie dla administratora serwera i grupy procesu aplikacji. Grupa musi odpowiadać `BAE_SECRET_GID`, katalog `750`, pliki `640`. Panel pokazuje gotowość pary i termin ważności, nigdy treść klucza.

Przy generowaniu CSR postępuj zgodnie z aktualną instrukcją dodania systemu; nie narzucamy fikcyjnego DN. Przykład utworzenia samego klucza:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out secrets/int.key
chmod 640 secrets/int.key
```

Certyfikat wydany dla systemu zarejestrowanego w module uprawnień nie jest certyfikatem HTTPS lokalnego panelu i nie jest ogólnym „kluczem API”.

## Uwierzytelnienie

Adapter korzysta z HTTPS do interfejsu operatora wyznaczonego. Nie próbuje łączyć urzędu bezpośrednio z centralnym interfejsem mTLS przeznaczonym dla OW/KDU.

| Element | INT | PROD |
|---|---|---|
| Host | `https://int-ow.edoreczenia.gov.pl` | `https://ow.edoreczenia.gov.pl` |
| Token | `/auth/realms/EDOR/protocol/openid-connect/token` | ten sam sufiks |
| Baza SE API | `/api/se/v4` | ten sam sufiks |
| Wyszukiwanie osoby | `POST /search/bae_search` | ta sama operacja |

Podpisana asercja RS256 zawiera `iss` i `sub` w formacie `ADE.SYSTEM.NAZWA_SYSTEMU`, `aud`, `iat`, `nbf`, `exp` i losowy `jti`. Do endpointu tokenowego trafiają `grant_type=client_credentials`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, podpisana asercja oraz parametr zapytania `login_hint`. Właściwe zapytanie SE otrzymuje `Authorization: Bearer …`.

Oficjalne przykłady różnią się zapisem `audience` (`http`/`https`) i `login_hint` (z prefiksem `ADE.` lub bez). Te pola pozostają puste do świadomego skonfigurowania przez administratora. Aplikacja dopuszcza tylko warianty wskazujące właściwy realm i własne ADE; nie zgaduje, który wariant zaakceptuje zarejestrowany system.

Token jest szyfrowany przed umieszczeniem w Redisie, współdzielony między procesami i używany do końca `expires_in`. Nie jest pobierany ponownie przy każdym wyszukiwaniu. Nie wpisujemy na sztywno historycznych okresów ważności. Po zmianie certyfikatu/nazwy systemu zaplanuj restart procesów i kontrolowane przełączenie; istniejący token może pozostać ważny do swojego terminu.

## Dostępne operacje i ograniczenia

Osoba: `recipientEdasOnly=false`, `searchCategory=["INDIVIDUAL"]`, `senderEda`, `name`, `surname`, a następnie `officialIds` z `referenceRegistry="pesel"` i tekstowym `id` albo tablica `address`. W adresie używane są `countryCode`, `city`, `postalCode`, `street`, `buildingNumber`, `flatNumber`. Wersja 4.0.5 nie wymaga numeru budynku w samym schemacie; aplikacja wymaga go w metodzie adresowej, żeby ograniczyć niedokładne wyszukiwanie. Ulica może pozostać pusta dla adresów bez ulic.

Kontrakt przewiduje limit wyników `bae_search` od 1 do 50. Adapter pobiera maksymalnie 2 wyniki i sprawdza `totalResults`; więcej niż jeden wynik oznacza ręczną weryfikację. Nie jest to limit liczby osób do sprawdzenia.

Istnieje zbiorcze `POST /search/eda-search` do maksymalnie 1000 **znanych ADE**, a także `eda-confirmation` dla własnego adresu. To nie jest wsadowe wyszukiwanie 1000 osób po PESEL. Dlatego import osób jest realizowany przez kolejkę pojedynczych zapytań.

Limit zapytań na sekundę zależy od uprawnień przyznanych przez dostawcę. Domyślne `0,5/s`, równoległość `1` i granice panelu `0,01–10/s`, `1–8` są ustawieniami lokalnymi aplikacji, a nie deklaracją limitów dostawcy. Połączenie wymaga osobnego potwierdzenia zgodności ustawień z uprawnieniami. Nie wolno zwiększać ich w celu obejścia ograniczeń operatora. Dla orientacji 100 000 rzeczywistych zapytań przy 0,5/s zajmie co najmniej około 55,6 h.

429, 500, 502, 503 i 504 oraz przejściowe błędy sieci są ponawiane z opóźnieniem i poszanowaniem `Retry-After`. 401/403 blokują zadanie i wymagają interwencji administratora. Kod 400 oznacza nieprawidłowe zapytanie, nie brak adresu. Nieprawidłowy JSON, niezgodność kontraktu i nieobsługiwane odpowiedzi są błędami technicznymi.

## Uruchomienie połączenia

Panel **Administracja** udostępnia ustawienia środowiska, ADE, nazwy systemu, audience, login hint i limitów. Po zapisaniu konfiguracji dostępny jest **Test autoryzacji**. Ten test pobiera token; nie dowodzi jeszcze uprawnienia do wyszukiwania konkretnej kategorii i nie odpytuje rejestru o przypadkową osobę.

Testy integracyjne na INT obejmują dopasowanie, brak dopasowania, błąd danych, odmowę uprawnień oraz niejednoznaczność. Czas, źródło i ADE podlegają porównaniu z systemem referencyjnym. Konfiguracja PROD następuje po odbiorze integracji na INT.

Nie zmieniaj środowiska przy działających zadaniach. Wstrzymaj je; zadanie utworzone dla INT nie jest wznawiane przeciwko PROD.

## Wersjonowanie adaptera

Oryginalny YAML jest w `contracts/`. Adapter izoluje budowę zapytania, interpretację odpowiedzi i autoryzację od pozostałych modułów. Nowa wersja API wymaga aktualizacji kontraktu, adaptera i testów. Aktualizacja adaptera nie wymaga przebudowy logiki importu ani interfejsu.

W opublikowanym YAML `AssignmentDegreeEnum` ma `type: string`, a wartości enum zapisano liczbowo. Oryginalny plik pozostaje bez zmian; walidator tworzy kopię w pamięci z tekstowymi wartościami enum i akceptuje w odpowiedzi tekstową lub liczbową reprezentację stopnia. Niejednoznaczne dane nadal wymagają kontroli operatora.
