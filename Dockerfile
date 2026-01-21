# Krok 1: Wybierz oficjalny obraz Pythona jako bazę.
# Używamy wersji "slim", która jest mniejsza i szybsza do pobrania.
FROM python:3.10-slim

# Krok 2: Ustaw katalog roboczy wewnątrz kontenera.
# Wszystkie kolejne komendy będą wykonywane w tym folderze.
WORKDIR /app

# Krok 3: Skopiuj plik z zależnościami do kontenera.
COPY requirements.txt .

# Krok 4: Zainstaluj zależności z pliku requirements.txt.
RUN pip install --no-cache-dir -r requirements.txt


# Krok 5: Skopiuj cały kod Twojego projektu do katalogu /app w kontenerze.
COPY . .
RUN python init_db.py

# Krok 6: Ustaw zmienne środowiskowe, aby Flask wiedział, jak uruchomić aplikację.
ENV FLASK_APP=src
ENV FLASK_RUN_HOST=0.0.0.0

# Krok 7: Odsłoń port 5000, aby można było się połączyć z aplikacją z zewnątrz kontenera.
EXPOSE 5000

# Krok 8: Zdefiniuj domyślną komendę, która uruchomi aplikację, gdy kontener wystartuje.
CMD ["flask", "run"]