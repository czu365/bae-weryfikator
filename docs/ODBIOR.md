# Macierz odbioru

| Wymaganie | Dostarczony element | Co wymaga potwierdzenia |
|---|---|---|
| Frontend i backend | React/TypeScript, FastAPI, pełne źródła i build | uruchomienie w LAN |
| Baza i migracje | PostgreSQL, SQLAlchemy, Alembic, 3 migracje | wykonanie na docelowym PostgreSQL |
| Rzeczywista integracja BAE | adapter oficjalnego YAML SE API 4.0.5, signed JWT, osobne INT/PROD | dostęp urzędu, certyfikat, uprawnienia, próba INT i PROD |
| Weryfikacja osoby | obie metody, walidacja, osobne wyniki i źródło | zgodność rzeczywistych wyników z BAE |
| Import masowy | CSV i JSON, podgląd, mapowanie, kontrola danych, do 100 000 | urzędowy format wejściowy, test zasobów serwera |
| Kolejka i wznowienie | PostgreSQL leases, Redis, retry, pauza, anulowanie, selektywne ponowienia | współbieżność i restart na docelowych usługach |
| Wyniki i eksport | paginacja, filtry, korekty, zaznaczanie, CSV/JSON/XLSX/PDF, własne nazwy pól | uzgodnienie formatu kancelaryjnego / EZD PUW |
| Użytkownicy i role | konta lokalne, LDAPS, administrator/operator/audytor, obowiązkowe TOTP | polityka kont, rzeczywisty AD, procedura resetów |
| Ochrona danych | szyfrowanie aplikacyjne, sekrety poza bazą, HMAC, audyt, retencja | konfiguracja magazynu i dysków, harmonogram backupu, ocena organizacyjna |
| Uruchomienie | Compose, Caddy TLS, healthchecki, backup i bezpieczne odtwarzanie | build i test odtworzenia w urzędzie |
| Testy | 50 testów, osobny test 100 000, kontrakty i HTTP mock | test rzeczywistej integracji i infrastruktury |
| Dostępność | semantyka, etykiety, focus, klawiatura, kontrast, responsywność | formalna weryfikacja WCAG 2.2 AA |

## Dane niezbędne do uruchomienia BAE

1. Autoryzowany dostęp INT podmiotu oraz dopuszczenie właściwych publicznych IP.
2. Zarejestrowane ADE i nazwa systemu; nadane uprawnienia wyszukiwania `INDIVIDUAL`.
3. Wydany certyfikat oraz odpowiadający klucz RSA dla INT, następnie osobna para PROD.
4. Potwierdzone `audience`, `login_hint`, limity zapytań i równoległości.
5. Aktualny kontrakt z chronionej dokumentacji INT do porównania z dołączonym publicznym plikiem.
6. Serwer LAN, nazwa DNS, zaufany TLS, konta operatorów i — jeśli używany — LDAPS.

Bez tych danych nie można uczciwie potwierdzić końcowego kryterium „rzeczywiste wyniki BAE po konfiguracji”. Ta paczka zawiera implementację, testy lokalne i instrukcje; nie udaje odebranego systemu produkcyjnego.

Nie zaimplementowano nadawania korespondencji, oficjalnego konektora importowego EZD PUW, importu XLSX, SSO/Kerberos, automatycznego mapowania grup AD, HSM ani automatycznej rotacji kluczy. Import XLSX był opcjonalny w specyfikacji; eksport XLSX jest dostępny. Aplikacja nie wybiera prawnego trybu doręczenia za operatora.
