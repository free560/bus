"""
╔══════════════════════════════════════════════════════════════════════╗
║             CRYPTO_UTILS.PY — MODULE CRYPTOGRAPHIQUE                ║
║         AES-256-GCM + PBKDF2-HMAC-SHA256 (Python 3.14)             ║
╚══════════════════════════════════════════════════════════════════════╝

Compatible : Python 3.14+ | cryptography==42.0.8

ALGORITHMES :
  ► AES-256-GCM       : Chiffrement authentifié (AEAD)
  ► PBKDF2-HMAC-SHA256: Dérivation de clé depuis mot de passe
  ► os.urandom()      : Génération aléatoire cryptographiquement sûre

PROPRIÉTÉS DE SÉCURITÉ :
  ✔ Confidentialité   — AES-256 rend le contenu illisible sans clé
  ✔ Intégrité         — Tag GCM détecte toute falsification
  ✔ Authenticité      — PBKDF2 lie la clé au bon mot de passe
  ✔ Anti-rainbow      — Sel unique par message
  ✔ Anti-rejeu        — Nonce unique par message
"""

# ─── Imports standard Python (tous présents en 3.14) ─────────────────
import os
import base64
from typing import Tuple

# ─── Imports cryptography 42.x ───────────────────────────────────────
# pip install cryptography==42.0.8
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag


# ─────────────────────────────────────────────────────────────────────
#  CONSTANTES CRYPTOGRAPHIQUES — NE PAS MODIFIER
# ─────────────────────────────────────────────────────────────────────

# Taille du sel : 128 bits (16 bytes) — protège contre les rainbow tables
TAILLE_SEL: int = 16

# Taille du nonce : 96 bits (12 bytes) — taille optimale pour AES-GCM
TAILLE_NONCE: int = 12

# Taille de la clé AES : 256 bits (32 bytes) — AES-256
TAILLE_CLE: int = 32

# Itérations PBKDF2 : 310 000 — recommandation OWASP 2023
# Plus ce nombre est élevé, plus les attaques par force brute sont lentes
ITERATIONS_PBKDF2: int = 310_000


# ─────────────────────────────────────────────────────────────────────
#  CLASSE : CryptoEngine
# ─────────────────────────────────────────────────────────────────────

class CryptoEngine:
    """
    Moteur cryptographique de Secure Chat.

    Toutes les méthodes sont statiques (pas d'état interne sensible).
    Aucune clé n'est jamais stockée en attribut de classe ou d'instance.
    """

    # ─────────────────────────────────────────────────────────────────
    # MÉTHODES DE GÉNÉRATION ALÉATOIRE
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def generer_sel() -> bytes:
        """
        Génère un sel aléatoire cryptographiquement sûr (128 bits).

        Rôle du sel :
          - Rend chaque dérivation de clé unique
          - Empêche les attaques par tables arc-en-ciel
          - Doit être stocké avec le message chiffré (non secret)

        Retourne :
            bytes : 16 octets aléatoires via os.urandom()
        """
        return os.urandom(TAILLE_SEL)

    @staticmethod
    def generer_nonce() -> bytes:
        """
        Génère un nonce (Number Used Once) pour AES-GCM (96 bits).

        ⚠️  CRITIQUE : Le nonce NE DOIT JAMAIS être réutilisé avec
        la même clé. Sinon, la sécurité de GCM est totalement compromise.

        Retourne :
            bytes : 12 octets aléatoires via os.urandom()
        """
        return os.urandom(TAILLE_NONCE)

    # ─────────────────────────────────────────────────────────────────
    # DÉRIVATION DE CLÉ
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def deriver_cle(mot_de_passe: str, sel: bytes) -> bytes:
        """
        Dérive une clé AES-256 depuis un mot de passe via PBKDF2.

        Fonctionnement de PBKDF2 :
          clé = PBKDF2(mot_de_passe, sel, itérations, longueur, hash)

          Avec 310 000 itérations SHA-256, un attaquant doit effectuer
          310 000 × N hachages pour tester N mots de passe → très lent.

        Arguments :
            mot_de_passe (str)  : Mot de passe utilisateur (texte libre)
            sel          (bytes): Sel aléatoire 128 bits (depuis generer_sel)

        Retourne :
            bytes : Clé dérivée de 32 octets (256 bits) pour AES-256

        Lève :
            ValueError : Si mot de passe vide ou None
        """
        if not mot_de_passe:
            raise ValueError("Le mot de passe ne peut pas être vide.")

        # Encodage UTF-8 du mot de passe (gère les accents, emoji, etc.)
        mdp_bytes = mot_de_passe.encode("utf-8")

        # Construction du dérivateur PBKDF2
        derivateur = PBKDF2HMAC(
            algorithm=hashes.SHA256(),    # Fonction de hachage interne
            length=TAILLE_CLE,            # 32 bytes = 256 bits
            salt=sel,                     # Sel unique anti-rainbow
            iterations=ITERATIONS_PBKDF2, # 310k itérations (lenteur voulue)
            backend=default_backend()     # Backend natif (OpenSSL via cffi)
        )

        # Dérivation et retour (ne jamais logger cette valeur !)
        return derivateur.derive(mdp_bytes)

    # ─────────────────────────────────────────────────────────────────
    # CHIFFREMENT
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def chiffrer(message: str, mot_de_passe: str) -> str:
        """
        Chiffre un message en clair avec AES-256-GCM.

        Étapes internes :
          1. Validation des entrées
          2. Génération d'un sel unique  (16 bytes)
          3. Génération d'un nonce unique (12 bytes)
          4. Dérivation de la clé AES-256 via PBKDF2
          5. Chiffrement avec AES-GCM → ciphertext + tag (16 bytes)
          6. Assemblage : SEL || NONCE || CIPHERTEXT_ET_TAG
          7. Encodage Base64 du payload final

        Payload encodé (Base64) :
          ┌─────────┬──────────┬──────────────────────────────┐
          │ SEL 16B │ NONCE 12B│ CIPHERTEXT + TAG GCM 16B     │
          └─────────┴──────────┴──────────────────────────────┘

        Arguments :
            message      (str) : Texte à chiffrer (UTF-8)
            mot_de_passe (str) : Mot de passe de chiffrement

        Retourne :
            str : Payload chiffré encodé en Base64

        Lève :
            ValueError : Entrées invalides
            Exception  : Erreur cryptographique inattendue
        """
        # ── Validation ────────────────────────────────────────────────
        if not message or not message.strip():
            raise ValueError("Le message à chiffrer est vide.")
        if not mot_de_passe:
            raise ValueError("Le mot de passe est requis pour chiffrer.")

        # ── Génération des valeurs aléatoires ─────────────────────────
        sel   = CryptoEngine.generer_sel()    # 128 bits
        nonce = CryptoEngine.generer_nonce()  # 96 bits

        # ── Dérivation de la clé ──────────────────────────────────────
        cle = CryptoEngine.deriver_cle(mot_de_passe, sel)

        try:
            # ── Chiffrement AES-256-GCM ───────────────────────────────
            # AESGCM.encrypt() retourne ciphertext || tag (concaténés)
            # Le tag de 16 bytes garantit l'INTÉGRITÉ du message
            aesgcm = AESGCM(cle)
            donnees = aesgcm.encrypt(nonce, message.encode("utf-8"), None)

            # ── Assemblage du payload ─────────────────────────────────
            # sel(16) + nonce(12) + donnees(len(message)+16)
            payload = sel + nonce + donnees

            # ── Encodage Base64 (transport et affichage) ──────────────
            return base64.b64encode(payload).decode("utf-8")

        finally:
            # Tentative de nettoyage de la clé en mémoire
            # (Python ne garantit pas l'effacement immédiat du GC)
            del cle

    # ─────────────────────────────────────────────────────────────────
    # DÉCHIFFREMENT
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def dechiffrer(payload_b64: str, mot_de_passe: str) -> str:
        """
        Déchiffre et vérifie l'authenticité d'un message AES-256-GCM.

        Étapes internes :
          1. Décodage Base64 du payload
          2. Extraction de : sel, nonce, données GCM
          3. Re-dérivation de la clé (même sel → même clé si bon mot de passe)
          4. Déchiffrement AES-GCM + vérification du tag
          5. Décodage UTF-8 du message clair

        ⚠️  Si le tag GCM échoue → InvalidTag levée.
            Cela signifie : mauvais mot de passe OU message falsifié.

        Arguments :
            payload_b64  (str) : Message chiffré en Base64
            mot_de_passe (str) : Mot de passe de déchiffrement

        Retourne :
            str : Message déchiffré en clair

        Lève :
            ValueError   : Payload ou mot de passe invalide
            InvalidTag   : Mauvais mot de passe ou données corrompues
        """
        # ── Validation ────────────────────────────────────────────────
        if not payload_b64:
            raise ValueError("Le payload chiffré est vide.")
        if not mot_de_passe:
            raise ValueError("Le mot de passe est requis pour déchiffrer.")

        # ── Décodage Base64 ───────────────────────────────────────────
        try:
            payload = base64.b64decode(payload_b64)
        except Exception:
            raise ValueError("Le payload Base64 est invalide ou corrompu.")

        # ── Vérification de la taille minimale ───────────────────────
        # Minimum : sel(16) + nonce(12) + tag GCM(16) = 44 bytes
        taille_min = TAILLE_SEL + TAILLE_NONCE + 16
        if len(payload) < taille_min:
            raise ValueError(
                f"Payload trop court : {len(payload)} bytes "
                f"(minimum requis : {taille_min} bytes)."
            )

        # ── Extraction des composants ─────────────────────────────────
        sel    = payload[:TAILLE_SEL]
        nonce  = payload[TAILLE_SEL : TAILLE_SEL + TAILLE_NONCE]
        donnees = payload[TAILLE_SEL + TAILLE_NONCE:]  # ciphertext + tag

        # ── Re-dérivation de la clé ───────────────────────────────────
        # Le même sel produit la même clé pour le même mot de passe
        cle = CryptoEngine.deriver_cle(mot_de_passe, sel)

        try:
            # ── Déchiffrement + vérification du tag GCM ───────────────
            aesgcm = AESGCM(cle)
            message_bytes = aesgcm.decrypt(nonce, donnees, None)

        except InvalidTag:
            # Tag invalide = mauvais mot de passe OU message falsifié
            raise InvalidTag(
                "Déchiffrement impossible : mot de passe incorrect "
                "ou message corrompu/falsifié."
            )
        except Exception as e:
            raise Exception(f"Erreur de déchiffrement inattendue : {e}")
        finally:
            del cle  # Nettoyage de la clé

        return message_bytes.decode("utf-8")

    # ─────────────────────────────────────────────────────────────────
    # UTILITAIRES
    # ─────────────────────────────────────────────────────────────────

    @staticmethod
    def valider_mot_de_passe(mdp: str) -> Tuple[bool, str]:
        """
        Valide la robustesse minimale d'un mot de passe.

        Règles :
          - Non vide
          - Non composé uniquement d'espaces
          - Longueur ≥ 6 caractères

        Arguments :
            mdp (str) : Mot de passe à valider

        Retourne :
            Tuple[bool, str] : (valide, message explicatif)
        """
        if not mdp:
            return False, "Mot de passe vide."
        if mdp.strip() == "":
            return False, "Le mot de passe ne contient que des espaces."
        if len(mdp) < 6:
            return False, f"Trop court ({len(mdp)}/6 caractères minimum)."
        return True, "✓ Mot de passe accepté"

    @staticmethod
    def tronquer(texte: str, max_chars: int = 52) -> str:
        """
        Tronque un texte pour l'affichage (évite les bulles trop larges).

        Arguments :
            texte     (str) : Texte à tronquer
            max_chars (int) : Longueur maximale avant troncature

        Retourne :
            str : Texte tronqué avec '…' si nécessaire
        """
        return texte if len(texte) <= max_chars else texte[:max_chars] + "…"

    @staticmethod
    def infos_securite() -> dict:
        """
        Retourne un dictionnaire des paramètres cryptographiques actifs.

        Utile pour l'affichage dans la console ou un écran "À propos".

        Retourne :
            dict : Paramètres cryptographiques
        """
        return {
            "Algorithme"    : "AES-256-GCM (AEAD)",
            "KDF"           : "PBKDF2-HMAC-SHA256",
            "Itérations"    : f"{ITERATIONS_PBKDF2:,}",
            "Taille clé"    : f"{TAILLE_CLE * 8} bits",
            "Taille sel"    : f"{TAILLE_SEL * 8} bits",
            "Taille nonce"  : f"{TAILLE_NONCE * 8} bits",
            "Intégrité"     : "Tag GCM 128 bits",
            "Compatible"    : "Python 3.14 · cryptography 42.x",
        }
