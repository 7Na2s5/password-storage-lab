import os
import hashlib
import secrets
import sqlite3
import subprocess
from hmac import compare_digest

from flask import Flask, render_template, request

from config import POLICY, GLOBAL_SALT, ENC_KEY, DB_NAME

app = Flask(__name__)


def get_db():
    # Connexion SQLite classique.
    conn = sqlite3.connect(DB_NAME)
    # Comme ca on peut acceder aux colonnes par nom (plus lisible que [0], [1], ...).
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    # On cree la table users au demarrage si elle n'existe pas deja.
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_plain TEXT,
            password_hash TEXT,
            salt TEXT,
            password_enc TEXT
        )
    """)
    conn.commit()
    conn.close()


def sha256_hex(value):
    # Hash SHA-256 en sortie hexadecimale.
    return hashlib.sha256(value.encode()).hexdigest()


def hash_password(password, salt=None):
    # Ici on adapte le hash selon la politique choisie dans config.py.
    if POLICY == 2:
        # Policy 2: hash direct du mot de passe.
        return sha256_hex(password)
    if POLICY == 3:
        # Policy 3: on ajoute un sel global avant de hasher.
        return sha256_hex(GLOBAL_SALT + password)
    if POLICY in (4, 5):
        # Policy 4/5: sel par utilisateur.
        return sha256_hex(salt + password)
    return None


def encrypt_password(password):
    # Chiffrement via openssl en ligne de commande (AES-256-CBC + PBKDF2).
    result = subprocess.run(
        [
            "openssl", "enc", "-aes-256-cbc", "-pbkdf2",
            "-a", "-salt", "-pass", "env:LAB_OPENSSL_KEY"
        ],
        env={**os.environ, "LAB_OPENSSL_KEY": ENC_KEY},
        input=password.encode(),
        capture_output=True,
        check=True
    )
    return result.stdout.decode().strip() # decode pour convertir de bytes a str et strip pour enlever les eventuels retours a la ligne.


def decrypt_password(ciphertext):
    # La version inverse, utile si on veut verifier/deboguer le contenu chiffre.
    result = subprocess.run(
        [
            "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
            "-a", "-salt", "-pass", "env:LAB_OPENSSL_KEY"
        ],
        env={**os.environ, "LAB_OPENSSL_KEY": ENC_KEY},
        input=ciphertext.encode(),
        capture_output=True,
        check=True
    )
    return result.stdout.decode().strip() # decode pour convertir de bytes a str et strip pour enlever les eventuels retours a la ligne.


@app.route("/", methods=["GET", "POST"])
def index():
    # Message affiche sur la page (erreur/succes selon le cas).
    message = ""

    if request.method == "POST":
        # On recupere l'action demandee et les champs du formulaire.
        action = request.form.get("action")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            # On bloque direct si un des deux champs est vide.
            return render_template("index.html", message="Nom d'utilisateur et mot de passe obligatoires.", policy=POLICY)

        conn = get_db()

        if action == "register":
            # On regarde d'abord si le username existe deja.
            existing = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if existing:
                message = "Utilisateur déjà existant."
            else:
                # On initialise tout a None et on remplit selon la policy.
                password_plain = None
                password_hash = None
                salt = None
                password_enc = None

                if POLICY == 1:
                    # Policy 1: stockage en clair.
                    password_plain = password
                elif POLICY == 2:
                    password_hash = hash_password(password)
                elif POLICY == 3:
                    password_hash = hash_password(password)
                elif POLICY == 4:
                    # Sel aleatoire propre a l'utilisateur.
                    salt = secrets.token_hex(16)
                    password_hash = hash_password(password, salt)
                elif POLICY == 5:
                    salt = secrets.token_hex(16)
                    password_hash = hash_password(password, salt)
                    password_enc = encrypt_password(password_hash)  # chiffre le HASH du mot de passe, pas le mot de passe lui-meme.

                # Insertion du nouvel utilisateur avec les champs correspondant a la policy active.
                conn.execute("""
                    INSERT INTO users (username, password_plain, password_hash, salt, password_enc)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, password_plain, password_hash, salt, password_enc))
                conn.commit()
                message = "Utilisateur enregistré."

        elif action == "login":
            # Connexion: on recupere l'utilisateur puis on compare le secret.
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            ).fetchone()

            if not user:
                message = "Utilisateur inconnu."
            else:
                ok = False

                if POLICY == 1:
                    # compare_digest evite les comparaisons naives un peu trop fragiles.
                    ok = compare_digest(user["password_plain"], password)

                elif POLICY in (2, 3):
                    # On re-hash le mot de passe saisi et on compare avec ce qui est stocke.
                    ok = compare_digest(user["password_hash"], hash_password(password))

                elif POLICY == 4:
                    ok = compare_digest(user["password_hash"], hash_password(password, user["salt"]))

                elif POLICY == 5:
                    # On recalcule le hash du mot de passe saisi
                    hash_saisi = hash_password(password, user["salt"])
                    # On déchiffre le hash stocké en BDD
                    hash_dechiffre = decrypt_password(user["password_enc"])
                    # On compare les deux hash
                    ok = compare_digest(hash_dechiffre, hash_saisi)
                
                message = "Connexion réussie." if ok else "Mot de passe incorrect."

        conn.close()

    return render_template("index.html", message=message, policy=POLICY)


if __name__ == "__main__":
    # Initialisation de la base puis lancement du serveur Flask.
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
