import sqlite3
from flask import g

DB_PATH = "market.db"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, isolation_level=None)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db(app):
    with app.app_context():
        db = get_db()
        with open("schema.sql") as f:
            db.executescript(f.read())
        db.commit()