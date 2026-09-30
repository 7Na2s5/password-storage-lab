import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import app as lab

class PoliciesTest(unittest.TestCase):
    def test_register_login_and_wrong_password(self):
        for policy in range(1, 6):
            if policy == 5 and not shutil.which("openssl"):
                self.skipTest("OpenSSL absent : politique 5 non vérifiée")
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as tmp:
                lab.POLICY = policy
                lab.DB_NAME = str(Path(tmp) / "synthetic.sqlite3")
                lab.ENC_KEY = secrets.token_hex(32)
                lab.init_db()
                client = lab.app.test_client()
                password = secrets.token_urlsafe(16)
                def post(action, pwd):
                    return client.post("/", data={"action":action,"username":"synthetic-user","password":pwd}).get_data(as_text=True)
                self.assertIn("enregistré", post("register", password))
                self.assertIn("réussie", post("login", password))
                self.assertIn("incorrect", post("login", password + "x"))
                with sqlite3.connect(lab.DB_NAME) as conn:
                    row = conn.execute("SELECT password_plain,password_hash,password_enc FROM users").fetchone()
                if policy == 1:
                    self.assertEqual(row[0], password)
                else:
                    self.assertNotIn(password, [str(x) for x in row])

if __name__ == "__main__": unittest.main()
