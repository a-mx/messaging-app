import sqlite3
import click
from flask import current_app, g

def get_db():
    """Nawiązuje połączenie z bazą danych, jeśli jeszcze nie istnieje dla danego żądania."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Zamyka połączenie z bazą danych."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_app(app):
    """Rejestruje funkcje związane z bazą danych w aplikacji."""
    app.teardown_appcontext(close_db) 
