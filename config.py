"""Configuration locale générée, sans secrets provenant du devoir."""
import os
import secrets
from pathlib import Path

POLICY = int(os.environ.get("LAB_POLICY", "4"))
if POLICY not in range(1, 6):
    raise ValueError("LAB_POLICY doit être compris entre 1 et 5")
GLOBAL_SALT = os.environ.get("LAB_GLOBAL_SALT", "synthetic-global-salt")
ENC_KEY = os.environ.get("LAB_ENCRYPTION_KEY", "")
if POLICY == 5 and not ENC_KEY:
    raise ValueError("La politique 5 exige LAB_ENCRYPTION_KEY, générée localement")
INSTANCE = Path(__file__).resolve().parent / "instance"
INSTANCE.mkdir(exist_ok=True)
DB_NAME = str(INSTANCE / f"users_policy_{POLICY}.sqlite3")
