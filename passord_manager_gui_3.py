#!/usr/bin/env python3
"""
Gestionnaire de mots de passe simplifié avec mot de passe maître.

Fonctions principales :
- Création / validation du mot de passe maître (clé dérivée via PBKDF2HMAC).
- Sauvegarde des mots de passe (Fernet) ; plusieurs comptes par site possibles.
- Recherche partielle et affichage dans une Listbox ; copier dans le presse-papier.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken
import base64, os, json, sys
import pathlib

# Optional clipboard library. If absent, we'll still work but copy will fail gracefully.
try:
    import pyperclip
    HAS_PYPERCLIP = True
except Exception:
    HAS_PYPERCLIP = False

# Files
DATA_FILE = "passwords.json"
SALT_FILE = "salt.bin"
VERIF_FILE = "verif.bin"   # contains a small ciphertext used to verify master password

# KDF params
KDF_ITERS = 390000
SALT_SIZE = 16

# ---------------- Utilities ----------------

def ensure_file_permissions(path: str):
    """Tentative pour limiter les permissions du fichier (Linux/Unix)."""
    try:
        os.chmod(path, 0o600)
    except Exception:
        # sur certains systèmes (Windows) chmod peut ne rien faire, on ignore l'erreur
        pass

def derive_key(password: str, salt: bytes) -> bytes:
    """Dérive une URL-safe base64 key utilisable par Fernet."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERS
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def init_storage_files():
    """Crée password.json si absent."""
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump({}, f, indent=4)
        ensure_file_permissions(DATA_FILE)

# ---------------- Master password flow ----------------

def create_master_password_flow(root):
    """Fenêtre de création mot de passe maître."""
    while True:
        pwd = simpledialog.askstring("Créer mot de passe maître",
                                     "Entrez un mot de passe maître (au moins 8 caractères):",
                                     show="*", parent=root)
        if pwd is None:
            return None
        if len(pwd) < 8:
            messagebox.showwarning("Mot de passe trop court", "Minimum 8 caractères.")
            continue
        pwd2 = simpledialog.askstring("Confirmer", "Confirmez le mot de passe:", show="*", parent=root)
        if pwd2 != pwd:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas.")
            continue
        # create salt and verifier
        salt = os.urandom(SALT_SIZE)
        key = derive_key(pwd, salt)
        f = Fernet(key)
        verif_token = f.encrypt(b"verifier-token-v1")
        # store
        with open(SALT_FILE, "wb") as s:
            s.write(salt)
        ensure_file_permissions(SALT_FILE)
        with open(VERIF_FILE, "wb") as v:
            v.write(verif_token)
        ensure_file_permissions(VERIF_FILE)
        return key  # return derived key to proceed

def ask_master_password_flow(root):
    """Fenêtre de saisie du mot de passe maître existant."""
    for attempt in range(3):
        pwd = simpledialog.askstring("Mot de passe maître",
                                     "Entrez votre mot de passe maître:", show="*", parent=root)
        if pwd is None:
            return None
        try:
            with open(SALT_FILE, "rb") as s:
                salt = s.read()
            key = derive_key(pwd, salt)
            f = Fernet(key)
            # try decrypt verifier
            with open(VERIF_FILE, "rb") as v:
                token = v.read()
            f.decrypt(token)  # si levée InvalidToken -> mot de passe incorrect
            return key
        except InvalidToken:
            messagebox.showerror("Erreur", "Mot de passe maître incorrect.")
        except FileNotFoundError:
            messagebox.showerror("Erreur", "Fichiers de configuration manquants.")
            return None
    messagebox.showerror("Trop d'essais", "Vous avez atteint le nombre maximum d'essais.")
    return None

# ---------------- Password store (uses derived key) ----------------

class PasswordStore:
    def __init__(self, fernet: Fernet):
        self.fernet = fernet
        init_storage_files()

    def load_all(self):
        try:
            with open(DATA_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            messagebox.showerror("Erreur", f"{DATA_FILE} est corrompu.")
            return {}
        except FileNotFoundError:
            return {}

    def save_all(self, data):
        with open(DATA_FILE, "w") as f:
            json.dump(data, f, indent=4)
        ensure_file_permissions(DATA_FILE)

    def add_entry(self, site: str, username: str, password: str):
        data = self.load_all()
        site_key = site.lower()
        entry = {"username": username, "password": self.fernet.encrypt(password.encode()).decode()}
        if site_key in data:
            # append to list
            if isinstance(data[site_key], list):
                data[site_key].append(entry)
            else:
                data[site_key] = [data[site_key], entry]
        else:
            data[site_key] = [entry]
        self.save_all(data)

    def search(self, query: str):
        """Search by substring in site name; returns list of tuples (site, index, username, password_plain)."""
        data = self.load_all()
        results = []
        q = query.lower()
        for site_key, entries in data.items():
            if q in site_key:
                if not isinstance(entries, list):
                    entries = [entries]
                for idx, e in enumerate(entries):
                    try:
                        pwd = self.fernet.decrypt(e["password"].encode()).decode()
                    except Exception:
                        pwd = "<decrypt error>"
                    results.append((site_key, idx, e.get("username", ""), pwd))
        return results

    def list_all(self):
        """Return all (site, idx, username, pwd)"""
        data = self.load_all()
        results = []
        for site_key, entries in data.items():
            if not isinstance(entries, list):
                entries = [entries]
            for idx, e in enumerate(entries):
                try:
                    pwd = self.fernet.decrypt(e["password"].encode()).decode()
                except Exception:
                    pwd = "<decrypt error>"
                results.append((site_key, idx, e.get("username", ""), pwd))
        return results

# ---------------- GUI ----------------

class App(tk.Tk):
    def __init__(self, store: PasswordStore):
        super().__init__()
        self.store = store
        self.title("🔐 Gestionnaire de mots de passe (Master)")
        self.geometry("600x400")

        # Top frame: add entry
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")

        ttk.Label(top, text="Site:").grid(row=0, column=0, sticky="e")
        self.entry_site = ttk.Entry(top, width=30)
        self.entry_site.grid(row=0, column=1, padx=4)

        ttk.Label(top, text="Utilisateur:").grid(row=1, column=0, sticky="e")
        self.entry_user = ttk.Entry(top, width=30)
        self.entry_user.grid(row=1, column=1, padx=4)

        ttk.Label(top, text="Mot de passe:").grid(row=2, column=0, sticky="e")
        self.entry_pwd = ttk.Entry(top, width=30, show="*")
        self.entry_pwd.grid(row=2, column=1, padx=4)

        self.show_var = tk.BooleanVar(value=False)
        btn_show = ttk.Checkbutton(top, text="Afficher mot de passe", variable=self.show_var, command=self.toggle_show)
        btn_show.grid(row=2, column=2, padx=6)

        ttk.Button(top, text="Ajouter", command=self.cmd_add).grid(row=3, column=1, sticky="w", pady=8)
        ttk.Button(top, text="Réinitialiser champs", command=self.clear_inputs).grid(row=3, column=1, sticky="e", pady=8)

        # Middle frame: search
        mid = ttk.Frame(self, padding=8)
        mid.pack(fill="x")
        ttk.Label(mid, text="Recherche:").grid(row=0, column=0, sticky="e")
        self.search_var = tk.StringVar()
        self.entry_search = ttk.Entry(mid, width=40, textvariable=self.search_var)
        self.entry_search.grid(row=0, column=1, padx=4)
        ttk.Button(mid, text="Rechercher", command=self.cmd_search).grid(row=0, column=2, padx=4)
        ttk.Button(mid, text="Afficher tout", command=self.cmd_list_all).grid(row=0, column=3, padx=4)

        # Bottom: results Listbox + details
        bottom = ttk.Frame(self, padding=8)
        bottom.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(bottom, height=10)
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        scrollbar = ttk.Scrollbar(bottom, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="left", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        details = ttk.Frame(bottom, padding=8)
        details.pack(side="left", fill="y", padx=10)

        ttk.Label(details, text="Détails:").pack(anchor="w")
        self.detail_var = tk.StringVar(value="")
        ttk.Label(details, textvariable=self.detail_var, foreground="blue", wraplength=200).pack(anchor="w")

        ttk.Button(details, text="Copier mot de passe", command=self.cmd_copy).pack(fill="x", pady=4)
        ttk.Button(details, text="Supprimer entrée (non réversible)", command=self.cmd_delete).pack(fill="x", pady=4)

        # Initially list all
        self.current_results = []  # list of tuples (site, idx, username, pwd)
        self.cmd_list_all()

    def toggle_show(self):
        if self.show_var.get():
            self.entry_pwd.config(show="")
        else:
            self.entry_pwd.config(show="*")

    def clear_inputs(self):
        self.entry_site.delete(0, tk.END)
        self.entry_user.delete(0, tk.END)
        self.entry_pwd.delete(0, tk.END)

    def cmd_add(self):
        site = self.entry_site.get().strip()
        user = self.entry_user.get().strip()
        pwd = self.entry_pwd.get().strip()
        if not (site and user and pwd):
            messagebox.showwarning("Champs incomplets", "Remplis Site, Utilisateur et Mot de passe.")
            return
        try:
            self.store.add_entry(site, user, pwd)
            messagebox.showinfo("Succès", f"Entrée ajoutée pour {site}.")
            self.clear_inputs()
            self.cmd_list_all()
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible d'ajouter l'entrée : {e}")

    def cmd_search(self):
        q = self.search_var.get().strip()
        if not q:
            messagebox.showwarning("Recherche vide", "Entre une chaîne à rechercher.")
            return
        self.current_results = self.store.search(q)
        self.update_listbox()

    def cmd_list_all(self):
        self.current_results = self.store.list_all()
        self.update_listbox()

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        for i, (site, idx, user, pwd) in enumerate(self.current_results):
            self.listbox.insert(tk.END, f"{site} — {user} (#{idx})")
        self.detail_var.set("")

    def on_select(self, event):
        sel = self.listbox.curselection()
        if not sel:
            return
        i = sel[0]
        site, idx, user, pwd = self.current_results[i]
        # hide password by default in details
        self.detail_var.set(f"Site: {site}\nUtilisateur: {user}\nMot de passe: {'*' * 8}  (clique Copier pour copier)")

    def cmd_copy(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("Aucune sélection", "Sélectionne d'abord une entrée.")
            return
        i = sel[0]
        site, idx, user, pwd = self.current_results[i]
        if HAS_PYPERCLIP:
            try:
                pyperclip.copy(pwd)
                messagebox.showinfo("Copié", "Mot de passe copié dans le presse-papier.")
                # optionally reveal in details briefly:
                self.detail_var.set(f"Site: {site}\nUtilisateur: {user}\nMot de passe: {pwd}")
            except Exception as e:
                messagebox.showerror("Erreur", f"Impossible de copier : {e}")
        else:
            # fallback: show password in a dialog (less secure)
            messagebox.showinfo("Mot de passe", f"{pwd}\n\nInstalle pyperclip pour copier automatiquement.")
            self.detail_var.set(f"Site: {site}\nUtilisateur: {user}\nMot de passe: {pwd}")

    def cmd_delete(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showwarning("Aucune sélection", "Sélectionne d'abord une entrée.")
            return
        i = sel[0]
        site, idx, user, pwd = self.current_results[i]
        if not messagebox.askyesno("Confirmer suppression", f"Supprimer l'entrée {user} @ {site} ?"):
            return
        data = self.store.load_all()
        entries = data.get(site, [])
        if not isinstance(entries, list):
            entries = [entries]
        try:
            entries.pop(idx)
            if entries:
                data[site] = entries
            else:
                data.pop(site, None)
            self.store.save_all(data)
            messagebox.showinfo("Supprimé", "Entrée supprimée.")
            self.cmd_list_all()
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de supprimer : {e}")

# ---------------- Main ----------------

def main():
    # Create a tiny root for dialogs
    root = tk.Tk()
    root.withdraw()  # hide

    # Check if master password exists
    if not (os.path.exists(SALT_FILE) and os.path.exists(VERIF_FILE)):
        # create new master password
        answer = messagebox.askyesno("Initialisation",
                                     "Aucun mot de passe maître trouvé. Voulez-vous en créer un maintenant ?")
        if not answer:
            messagebox.showinfo("Quit", "L'application va se fermer.")
            root.destroy()
            sys.exit(0)
        key_bytes = create_master_password_flow(root)
        if key_bytes is None:
            messagebox.showinfo("Quit", "Configuration incomplète — fermeture.")
            root.destroy()
            sys.exit(0)
    else:
        key_bytes = ask_master_password_flow(root)
        if key_bytes is None:
            root.destroy()
            sys.exit(0)

    # Hide root and launch main app window
    root.destroy()
    f = Fernet(key_bytes)
    store = PasswordStore(f)
    app = App(store)
    app.mainloop()

if __name__ == "__main__":
    main()
