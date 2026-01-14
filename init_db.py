import sqlite3

DATABASE = "sqlite3.db"
db = sqlite3.connect(DATABASE)

with open('schema.sql') as f:
    db.executescript(f.read())

db.commit()
db.close()