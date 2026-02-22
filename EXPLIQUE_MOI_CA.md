# 🛡️ C'est quoi ce projet ? — Explication simple

> Ce projet s'appelle **Zero-Day Prevention System**.
> C'est un mini-logiciel de sécurité (comme un antivirus maison) écrit en Python.
> Il surveille ton Mac en temps réel et te prévient si quelque chose de suspect se passe.

---

## 🗺️ Vue d'ensemble — Le grand schéma

```
Tu lances main.py
        │
        ├──► ProcessMonitor   → surveille les processus (programmes qui tournent)
        ├──► FileMonitor      → surveille les fichiers (créations, modifs, suppressions)
        ├──► NetworkMonitor   → surveille les connexions réseau sortantes
        └──► Dashboard        → une page web sur http://localhost:5001 pour voir les alertes
```

Tout tourne **en parallèle** (grâce aux "threads") et s'arrête d'un seul `Ctrl+C`.

---

## 📁 Structure des fichiers — À quoi sert chaque fichier

```
cyberproject/
├── main.py                  ← Le chef d'orchestre. Lance tout.
├── whitelist.json           ← Liste des programmes "de confiance"
├── requirements.txt         ← Les bibliothèques Python nécessaires
│
├── engine/
│   └── detection_engine.py  ← Le cerveau : décide si un process est suspect
│
├── agent/
│   ├── process_monitor.py   ← Regarde les nouveaux programmes qui se lancent
│   └── prevention.py        ← Écrit les alertes dans un fichier JSON
│
├── file_monitor/
│   └── file_monitor.py      ← Surveille les fichiers (ajout/modif/suppression)
│
├── network/
│   └── network_monitor.py   ← Surveille les connexions Internet
│
├── dashboard/
│   └── app.py               ← Un site web Flask pour voir les alertes
│
└── logs/
    └── alerts.json          ← Toutes les alertes sauvegardées ici
```

---

## 🔍 Comment ça détecte un processus suspect ? (le cœur du projet)

Le fichier **`engine/detection_engine.py`** est le plus important.
Il contient une fonction `is_process_suspicious()` qui reçoit les infos d'un programme
et dit `True` (suspect) ou `False` (pas suspect).

### La logique, dans l'ordre :

```
Étape 1 — Le chemin est-il de confiance ?
    → Si le programme vient de /System/, /usr/, /Applications/, /Library/, /opt/homebrew/
    → OUI → Pas suspect. STOP. (C'est un programme Apple ou Homebrew, c'est normal)

Étape 2 — Est-ce un helper de navigateur ?
    → Si le nom contient "Helper", "Renderer", "GPU", "WebKit", "mdworker"
    → OUI → Pas suspect. STOP. (C'est Chrome/Safari qui fait son boulot)

Étape 3 — Le fichier exécutable existe vraiment et n'est pas dans un endroit risqué ?
    → Si oui ET que le nom est dans whitelist.json → Pas suspect.
    → MAIS si CPU > 85% ou RAM > 800 Mo → Suspect quand même ! (comportement anormal)

Étape 4 — Le programme vient-il d'un endroit dangereux ?
    → /tmp/, /var/tmp/, /private/tmp/, ou ~/Downloads
    → OUI → Suspect ! STOP. (Les malwares s'exécutent souvent depuis ces dossiers)

Étape 5 — Le nom est-il inconnu ET le chemin pas de confiance ?
    → Si le nom N'EST PAS dans whitelist.json ET le chemin n'est pas sûr
    → OUI → Suspect !

Étape 6 — Trop de ressources ?
    → CPU > 85% ou RAM > 800 Mo
    → OUI → Suspect ! (peut être un cryptominer, ransomware, etc.)

    → Si rien de tout ça → Pas suspect. ✅
```

---

## 📋 C'est quoi `whitelist.json` ?

C'est une **liste blanche** : les programmes que tu fais confiance par leur nom.

```json
{
  "whitelist": ["bash", "python3", "nginx", "Code Helper", ...]
}
```

> ⚡ **Hot-reload** : tu peux modifier ce fichier pendant que le système tourne,
> il sera rechargé automatiquement sans redémarrer. Pas besoin de Ctrl+C.

---

## 🔄 Comment ça fonctionne en temps réel — Le flux complet

```
1. process_monitor.py  →  détecte un NOUVEAU PID (nouveau programme lancé)
         │
         ▼
2. detection_engine.py →  is_process_suspicious() → True ou False ?
         │
    [Suspect ?]
         │ OUI
         ▼
3. prevention.py       →  log_alert() → écrit dans logs/alerts.json
         │
         ▼
4. dashboard/app.py    →  lit alerts.json → l'affiche sur http://localhost:5001
```

---

## 🌐 Le Dashboard — La page web

Quand tu lances `python main.py`, tu peux ouvrir **http://localhost:5001** dans ton navigateur.

Tu y verras un tableau avec toutes les alertes :
- L'heure de l'alerte
- Le nom du programme suspect
- Son PID (numéro de processus)
- Son % CPU et sa RAM
- Son chemin sur le disque

La page se rafraîchit automatiquement toutes les **10 secondes**.

Il y a aussi une API REST :
```
GET http://localhost:5001/api/alerts   → renvoie toutes les alertes en JSON
```

---

## 🚀 Comment lancer le projet

```bash
# 1. Activer l'environnement Python
source .venv/bin/activate

# 2. Lancer tout le système
python main.py
```

Tu verras dans le terminal :
```
[*] Started thread: ProcessMonitor
[*] Started thread: FileMonitor
[*] Started thread: NetworkMonitor
[*] Started thread: Dashboard
[*] Dashboard available at http://localhost:5001
[*] Zero-day prevention system running. Press Ctrl+C to stop.
```

Pour arrêter : **Ctrl+C**

---

## 💡 Résumé en une phrase

> Ce projet surveille ton Mac en temps réel (processus, fichiers, réseau),
> détecte les comportements suspects grâce à un moteur de détection intelligent
> (chemin de confiance + whitelist + seuils CPU/RAM),
> et affiche les alertes sur un dashboard web.

---

## 🧠 Les concepts clés à retenir

| Concept | Explication simple |
|---|---|
| **Thread** | Un "sous-programme" qui tourne en parallèle |
| **Whitelist** | Liste des programmes autorisés par leur nom |
| **Trusted path** | Chemin système considéré comme sûr (`/System/`, etc.) |
| **PID** | Numéro unique d'un processus (programme en cours) |
| **psutil** | Bibliothèque Python pour lire les infos système (CPU, RAM, processus) |
| **Watchdog** | Bibliothèque Python pour surveiller les fichiers |
| **Flask** | Micro-framework Python pour faire des sites web simples |
| **False positive** | Fausse alerte — un programme normal détecté à tort comme suspect |
