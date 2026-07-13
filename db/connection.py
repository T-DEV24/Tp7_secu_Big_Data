"""
db/connection.py
Centralise la connexion MongoDB pour éviter de la recréer partout.
"""
from pymongo import MongoClient
import os

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME   = os.getenv("DB_NAME", "hopital_db")

_client = None

def get_db():
    """Retourne l'instance de la base de données (singleton)."""
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI)
    return _client[DB_NAME]

def get_collection(name: str):
    """Raccourci pour obtenir une collection par son nom."""
    return get_db()[name]