# Audyt sprawdzeń i eksportów

Widok administratora: **Historia zadań → Sprawdzenia i eksporty**. Formularz obejmuje daty **Od** i **Do** oraz rodzaj operacji. Obie daty są włączne w lokalnej strefie czasowej przeglądarki. Raport CSV podaje czas w UTC.

**Pokaż raport** wyświetla listę zdarzeń. **Pokaż** w kolumnie **Szczegóły** otwiera dane zdarzenia. **Pobierz CSV** eksportuje wszystkie strony ostatniego zastosowanego filtra.

| Zdarzenie | Zapisywany zakres |
|---|---|
| Próba sprawdzenia | Login zlecającego, ID właściciela zadania, środowisko, metoda, kryteria, status i numer próby |
| Eksport CSV, JSON, XLSX | Login, format, filtr, liczba wierszy, nazwy kolumn i wartości wyeksportowanych wierszy, z maskowaniem PESEL zgodnym z eksportem |
| Eksport PDF | Login, filtr, liczba wierszy i liczności statusów ujęte w zestawieniu |

Każda zarejestrowana próba workera ma osobny wpis. Duplikaty współdzielą jedno zapytanie. Próba może zakończyć się błędem autoryzacji lub połączenia przed wysłaniem zapytania do BAE. Zdarzenie eksportu potwierdza wygenerowanie pliku i gotowość do wysłania go w odpowiedzi HTTP.

W CSV główny wiersz zawiera metadane operacji. Kolejne wiersze z tym samym ID zawierają wartości eksportu w kolumnie **Szczegóły JSON**. Dla wpisów sprzed 0.2.1 dostępne są metadane zachowane w dzienniku. Operacje bez zapisanego zlecającego mają oznaczenie **Nieustalony**.

## Dostęp i retencja

Lista, szczegóły i pobranie raportu wymagają roli administratora. Podgląd szczegółów i wygenerowanie raportu mają osobne wpisy w dzienniku. Raport może zawierać pełne dane osobowe.

Szczegóły w bazie są szyfrowane i zachowywane po usunięciu zadania aż do upływu retencji audytu. Retencję określa ustawienie w **Administracja → Połączenie i retencja**. Pojemność bazy i kopii zapasowych zależy także od liczby i wielkości eksportów.
