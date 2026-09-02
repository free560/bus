"""
╔══════════════════════════════════════════════════════════════════════╗
║              MAIN.PY — LOGIQUE APPLICATIVE                          ║
║         Secure Chat · Python 3.14 · KivyMD 1.1.1                   ║
╚══════════════════════════════════════════════════════════════════════╝

Ce fichier contient UNIQUEMENT la logique applicative :
  - Définition des classes de widgets (sans style)
  - Gestion des événements (clic, saisie)
  - Orchestration chiffrement / déchiffrement
  - Animations programmatiques

Tout le style et la mise en page est dans : secure_chat.kv

LANCEMENT :
  python main.py

DÉPENDANCES :
  pip install -r requirements.txt
"""

# ─── Imports standard Python 3.14 ────────────────────────────────────
import os
from datetime import datetime

# ─── Configuration Kivy AVANT tout autre import Kivy ─────────────────
# Doit se faire avant "from kivy.app import App"
os.environ.setdefault("KIVY_NO_CONSOLELOG", "0")

# ─── Imports Kivy ────────────────────────────────────────────────────
from kivy.clock import Clock
from kivy.animation import Animation
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.widget import Widget
from kivy.metrics import dp, sp
from kivy.properties import StringProperty

# ─── Imports KivyMD 1.1.1 ────────────────────────────────────────────
from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.card import MDCard
from kivymd.uix.label import MDLabel
from kivymd.uix.button import MDRaisedButton, MDIconButton
from kivymd.uix.textfield import MDTextField

# ─── Import module cryptographique local ──────────────────────────────
from crypto_utils import CryptoEngine
from cryptography.exceptions import InvalidTag


# ─── Configuration initiale de la fenêtre ────────────────────────────
# Taille simulant un smartphone en mode portrait
Window.size = (420, 820)


# ─────────────────────────────────────────────────────────────────────
#  WIDGET : BulleEnvoye — Message envoyé (déclaré en KV)
# ─────────────────────────────────────────────────────────────────────

class BulleEnvoye(BoxLayout):
    """
    Bulle de message envoyé.
    Le style complet est défini dans secure_chat.kv (<BulleEnvoye>).

    Propriétés KV exposées :
        texte_original  : Message en clair
        texte_chiffre   : Payload Base64 (tronqué)
        texte_dechiffre : Message déchiffré
        horodatage      : Heure d'envoi formatée
    """
    # Propriétés Kivy (synchronisées avec le fichier .kv)
    texte_original  = StringProperty("")
    texte_chiffre   = StringProperty("")
    texte_dechiffre = StringProperty("")
    horodatage      = StringProperty("")


class BulleRecu(BoxLayout):
    """
    Bulle de message reçu.
    Style défini dans secure_chat.kv (<BulleRecu>).

    Propriétés identiques à BulleEnvoye.
    """
    texte_original  = StringProperty("")
    texte_chiffre   = StringProperty("")
    texte_dechiffre = StringProperty("")
    horodatage      = StringProperty("")


class BulleErreur(BoxLayout):
    """
    Notification d'erreur inline dans le chat.
    Disparaît automatiquement après 4 secondes.
    Style défini dans secure_chat.kv (<BulleErreur>).
    """
    texte_erreur = StringProperty("")


class EcranBienvenue(BoxLayout):
    """
    Écran de bienvenue affiché au démarrage.
    Style défini dans secure_chat.kv (<EcranBienvenue>).
    """
    pass


# ─────────────────────────────────────────────────────────────────────
#  WIDGET : ZoneSaisie — Zone de saisie (logique uniquement)
# ─────────────────────────────────────────────────────────────────────

class ZoneSaisie(MDBoxLayout):
    """
    Zone de saisie inférieure.
    Le style (MDTextField, MDRaisedButton) est dans secure_chat.kv.

    Ce fichier gère uniquement :
      - La référence aux champs (ids définis dans le .kv)
      - Le callback d'envoi (défini depuis SecureChatLayout)
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Le callback d'envoi sera assigné par SecureChatLayout
        # après le chargement du fichier KV
        self.callback_envoi = None


# ─────────────────────────────────────────────────────────────────────
#  WIDGET : SecureChatLayout — Layout principal (logique)
# ─────────────────────────────────────────────────────────────────────

class SecureChatLayout(MDBoxLayout):
    """
    Layout principal orchestrant toute l'application.

    Responsabilités :
      - Écouter le bouton Envoyer (défini dans .kv)
      - Appeler CryptoEngine.chiffrer() et .dechiffrer()
      - Créer les bulles de messages et les insérer dans le chat
      - Gérer le défilement automatique
      - Afficher les erreurs

    Le style est entièrement dans secure_chat.kv.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Compteur pour alterner envoyé/reçu (simulation conversation)
        self._compteur = 0

        # Connexion du bouton Envoyer après chargement complet du KV
        Clock.schedule_once(self._connecter_bouton, 0)

    def _connecter_bouton(self, dt):
        """
        Connecte le bouton Envoyer (défini dans le .kv) au handler Python.

        Appelé par Clock.schedule_once après que le fichier KV
        a été entièrement chargé et les ids résolus.
        """
        try:
            # Accès au bouton via l'id défini dans secure_chat.kv
            bouton = self.ids.bouton_envoi_id
            bouton.bind(on_press=self._sur_envoi)
        except Exception as e:
            print(f"[WARN] Connexion bouton différée : {e}")
            # Réessaie dans 100ms si les ids ne sont pas encore prêts
            Clock.schedule_once(self._connecter_bouton, 0.1)

    # ─────────────────────────────────────────────────────────────────
    # HANDLER PRINCIPAL : Envoi d'un message
    # ─────────────────────────────────────────────────────────────────

    def _sur_envoi(self, instance):
        """
        Gestionnaire du bouton Envoyer.

        Processus complet :
          1. Lecture des champs message et mot de passe
          2. Validation basique
          3. Chiffrement AES-256-GCM
          4. Déchiffrement immédiat (simulation réception)
          5. Affichage de la bulle dans le chat
          6. Nettoyage du champ message

        Arguments :
            instance : Widget bouton (non utilisé directement)
        """
        # ── Lecture des champs ────────────────────────────────────────
        message      = self.ids.champ_message_id.text.strip()
        mot_de_passe = self.ids.champ_mdp_id.text.strip()

        # ── Validation UI ─────────────────────────────────────────────
        if not message:
            self._afficher_erreur("⚠  Veuillez saisir un message.")
            self._animer_champ_vide(self.ids.champ_message_id)
            return

        if not mot_de_passe:
            self._afficher_erreur("⚠  Veuillez saisir un mot de passe.")
            self._animer_champ_vide(self.ids.champ_mdp_id)
            return

        # ── Validation du mot de passe ────────────────────────────────
        valide, msg_val = CryptoEngine.valider_mot_de_passe(mot_de_passe)
        if not valide:
            self._afficher_erreur(f"⚠  {msg_val}")
            self._animer_champ_vide(self.ids.champ_mdp_id)
            return

        # ── Horodatage ────────────────────────────────────────────────
        horodatage = datetime.now().strftime("%H:%M:%S")

        # ── Chiffrement ───────────────────────────────────────────────
        try:
            chiffre = CryptoEngine.chiffrer(message, mot_de_passe)
        except Exception as e:
            self._afficher_erreur(f"Erreur de chiffrement : {e}")
            return

        # ── Déchiffrement (simulation réception immédiate) ─────────────
        try:
            dechiffre = CryptoEngine.dechiffrer(chiffre, mot_de_passe)
        except InvalidTag:
            self._afficher_erreur("❌  Tag GCM invalide — déchiffrement impossible.")
            return
        except Exception as e:
            self._afficher_erreur(f"Erreur de déchiffrement : {e}")
            return

        # ── Troncature du payload pour l'affichage ────────────────────
        chiffre_affichage = CryptoEngine.tronquer(chiffre, 52)

        # ── Alternance envoyé / reçu ──────────────────────────────────
        self._compteur += 1
        est_envoye = (self._compteur % 2 == 1)

        # ── Création et ajout de la bulle ─────────────────────────────
        self._ajouter_bulle(
            texte_original  = message,
            texte_chiffre   = chiffre_affichage,
            texte_dechiffre = dechiffre,
            horodatage      = horodatage,
            est_envoye      = est_envoye,
        )

        # ── Log console (pour débogage) ───────────────────────────────
        self._logger_message(message, chiffre, dechiffre, est_envoye)

        # ── Nettoyage du champ message ────────────────────────────────
        self.ids.champ_message_id.text = ""
        # On conserve le mot de passe pour faciliter l'utilisation

        # ── Défilement vers le bas ────────────────────────────────────
        Clock.schedule_once(self._defiler_bas, 0.12)

    # ─────────────────────────────────────────────────────────────────
    # GESTION DES BULLES
    # ─────────────────────────────────────────────────────────────────

    def _ajouter_bulle(
        self,
        texte_original: str,
        texte_chiffre: str,
        texte_dechiffre: str,
        horodatage: str,
        est_envoye: bool,
    ):
        """
        Crée une bulle (envoyée ou reçue) et l'ajoute au conteneur.

        La bulle est d'abord invisible (opacity=0), puis un fade-in
        est déclenché via Clock pour l'animation d'apparition.

        Arguments :
            texte_original  : Message en clair
            texte_chiffre   : Payload Base64 tronqué
            texte_dechiffre : Message déchiffré
            horodatage      : Heure formatée
            est_envoye      : True = bulle noire droite, False = bulle or gauche
        """
        # Sélection du type de bulle
        if est_envoye:
            bulle = BulleEnvoye(
                texte_original  = texte_original,
                texte_chiffre   = texte_chiffre,
                texte_dechiffre = texte_dechiffre,
                horodatage      = horodatage,
            )
        else:
            bulle = BulleRecu(
                texte_original  = texte_original,
                texte_chiffre   = texte_chiffre,
                texte_dechiffre = texte_dechiffre,
                horodatage      = horodatage,
            )

        # Animation fade-in : commence transparent
        bulle.opacity = 0.0

        # Ajout dans le conteneur de messages
        self.ids.conteneur_id.add_widget(bulle)

        # Déclenche le fade-in après un court délai (rendu de la bulle)
        Clock.schedule_once(
            lambda dt, b=bulle: Animation(opacity=1.0, duration=0.4, t="out_quad").start(b),
            0.05
        )

    def _afficher_erreur(self, texte: str):
        """
        Affiche une bulle d'erreur temporaire dans le chat.

        La bulle disparaît automatiquement après 4 secondes.

        Arguments :
            texte (str) : Message d'erreur à afficher
        """
        bulle = BulleErreur(texte_erreur=texte)
        bulle.opacity = 0.0

        self.ids.conteneur_id.add_widget(bulle)

        # Fade-in de la bulle d'erreur
        Animation(opacity=1.0, duration=0.25).start(bulle)

        # Suppression automatique après 4s (fade-out puis remove)
        def _supprimer(dt):
            anim = Animation(opacity=0.0, duration=0.4)
            anim.bind(on_complete=lambda a, w: (
                self.ids.conteneur_id.remove_widget(w)
                if w in self.ids.conteneur_id.children else None
            ))
            anim.start(bulle)

        Clock.schedule_once(_supprimer, 4.0)

        # Défilement pour voir l'erreur
        Clock.schedule_once(self._defiler_bas, 0.1)

    # ─────────────────────────────────────────────────────────────────
    # ANIMATIONS
    # ─────────────────────────────────────────────────────────────────

    def _animer_champ_vide(self, champ):
        """
        Animation de secousse horizontale sur un champ vide.
        Retour visuel immédiat pour l'utilisateur.

        Arguments :
            champ : Widget MDTextField à animer
        """
        x_origine = champ.x
        anim = (
            Animation(x=x_origine + dp(6),  duration=0.05) +
            Animation(x=x_origine - dp(6),  duration=0.05) +
            Animation(x=x_origine + dp(4),  duration=0.05) +
            Animation(x=x_origine - dp(4),  duration=0.05) +
            Animation(x=x_origine,          duration=0.05)
        )
        anim.start(champ)

    # ─────────────────────────────────────────────────────────────────
    # DÉFILEMENT
    # ─────────────────────────────────────────────────────────────────

    def _defiler_bas(self, dt):
        """
        Défile automatiquement le ScrollView vers le dernier message.
        Appelé via Clock.schedule_once pour laisser le temps au rendu.
        """
        try:
            scroll = self.ids.scroll_view_id
            # scroll_y=0 = bas du ScrollView dans Kivy
            Animation(scroll_y=0, duration=0.3, t="out_quad").start(scroll)
        except Exception:
            pass  # Silencieux si le scroll n'est pas encore prêt

    # ─────────────────────────────────────────────────────────────────
    # LOGGING CONSOLE
    # ─────────────────────────────────────────────────────────────────

    def _logger_message(
        self,
        original: str,
        chiffre: str,
        dechiffre: str,
        est_envoye: bool
    ):
        """
        Affiche les détails d'un message dans la console Python.
        Utile pour le débogage et la démonstration.

        Arguments :
            original   : Message en clair
            chiffre    : Payload Base64 complet
            dechiffre  : Message déchiffré
            est_envoye : Direction du message
        """
        direction = "→ ENVOYÉ" if est_envoye else "← REÇU"
        print(f"\n{'─'*52}")
        print(f"  {direction}  [{datetime.now().strftime('%H:%M:%S')}]")
        print(f"  Original   : {original}")
        print(f"  Chiffré    : {chiffre[:60]}…")
        print(f"  Déchiffré  : {dechiffre}")
        print(f"{'─'*52}")


# ─────────────────────────────────────────────────────────────────────
#  APPLICATION : SecureChatApp
# ─────────────────────────────────────────────────────────────────────

class SecureChatApp(MDApp):
    """
    Classe principale KivyMD.

    Responsabilités :
      - Charger le fichier secure_chat.kv (automatique via le nom)
      - Configurer le thème Material Design
      - Construire le widget racine
      - Gérer le cycle de vie de l'application
    """

    # ── Titre de la fenêtre OS ────────────────────────────────────────
    title = "🔐 Secure Chat — AES-256-GCM"

    def build(self):
        """
        Construit l'application.

        KivyMD charge automatiquement 'secure_chat.kv' car
        le nom de l'app est 'securechat' → Kivy cherche 'securechat.kv'.
        On charge manuellement pour garder le nom 'secure_chat.kv'.

        Retourne :
            SecureChatLayout : Widget racine de l'application
        """
        # ── Configuration du thème KivyMD ─────────────────────────────
        self.theme_cls.theme_style = "Light"          # Fond clair
        self.theme_cls.primary_palette = "Yellow"     # Couleur principale : or
        self.theme_cls.accent_palette = "Gray"        # Accent : gris
        self.theme_cls.primary_hue = "A700"           # Teinte vive

        # ── Chargement manuel du fichier KV ───────────────────────────
        from kivy.lang import Builder
        Builder.load_file("secure_chat.kv")

        # ── Affichage des paramètres cryptographiques ─────────────────
        self._afficher_infos_securite()

        # ── Ajout du message de bienvenue après démarrage ─────────────
        # (les ids ne sont disponibles qu'après build)
        layout = SecureChatLayout()
        Clock.schedule_once(lambda dt: self._ajouter_bienvenue(layout), 0.2)

        return layout

    def _ajouter_bienvenue(self, layout):
        """
        Ajoute l'écran de bienvenue dans le conteneur de chat.

        Appelé après que les ids KV sont résolus.

        Arguments :
            layout (SecureChatLayout) : Layout principal
        """
        try:
            bienvenue = EcranBienvenue()
            bienvenue.opacity = 0.0
            layout.ids.conteneur_id.add_widget(bienvenue)
            Animation(opacity=1.0, duration=0.6, t="out_cubic").start(bienvenue)
        except Exception as e:
            print(f"[INFO] Bienvenue non affichée : {e}")

    def _afficher_infos_securite(self):
        """
        Affiche les paramètres de sécurité actifs dans la console.
        """
        infos = CryptoEngine.infos_securite()
        print("\n" + "═" * 54)
        print("   🔐  SECURE CHAT — PARAMÈTRES ACTIFS")
        print("═" * 54)
        for cle, val in infos.items():
            print(f"   ► {cle:<18} : {val}")
        print("═" * 54 + "\n")

    def on_start(self):
        """Appelé quand l'application est entièrement démarrée."""
        print("✅  Secure Chat démarré — Python 3.14 · KivyMD 1.1.1")

    def on_stop(self):
        """Appelé à la fermeture de l'application."""
        print("🔒  Secure Chat fermé proprement.")

    def get_application_name(self):
        """
        Retourne le nom de l'application pour Kivy.
        KivyMD 1.1.1 utilise ce nom pour trouver le fichier .kv
        si Builder.load_file n'est pas utilisé explicitement.
        """
        return "securechat"


# ─────────────────────────────────────────────────────────────────────
#  POINT D'ENTRÉE
# ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    """
    Lance l'application Secure Chat.

    Usage :
        python main.py

    Prérequis :
        pip install -r requirements.txt
    """
    SecureChatApp().run()
