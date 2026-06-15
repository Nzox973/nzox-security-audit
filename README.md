# 🔐 Nzox Security Audit Tool

Outil d'audit Windows défensif en Python.  
Analyse l'état de sécurité du PC et génère un rapport HTML clair.

**Auteur** : Enzo ATTICOT  
**Contexte** : Projet portfolio — Terminale NSI / BUT Informatique  
**Objectif** : Cybersécurité défensive, Python, Windows internals

---

## Fonctionnalités

| Vérification | Description |
|---|---|
| Informations système | OS, version, architecture |
| Espace disque | Utilisation de chaque partition, alertes si > 75% |
| Processus lourds | Top 10 par RAM (CPU + mémoire) |
| Démarrage | Programmes enregistrés au démarrage (registre) |
| Ports ouverts | Ports en écoute + processus associés |
| Windows Defender | État protection temps réel et antivirus |
| Mises à jour | Date de dernière vérification Windows Update |
| Interfaces réseau | Interfaces actives + adresses IP |

---

## Installation

```bash
pip install psutil
```

---

## Utilisation

```bash
# Rapport HTML (défaut)
python audit.py

# Rapport HTML explicite
python audit.py --html

# Rapport Markdown
python audit.py --md

# Les deux
python audit.py --html --md
```

Les rapports sont sauvegardés dans `reports/audit_YYYYMMDD_HHMMSS.html`.

---

## Exemple de sortie

```
🔐 Nzox Security Audit Tool — démarrage...

  → System Info...
  → Disk Space...
  → Top Processes...
  → Startup Programs...
  → Open Ports...
  → Defender...
  → Windows Updates...
  → Network Interfaces...

==================================================
Audit terminé — 1 point(s) à vérifier sur 8 sections.
Rapport sauvegardé dans : reports/
==================================================
```

---

## Sécurité & Éthique

- **100% défensif** — aucune modification système
- **Aucune donnée envoyée** — tout reste local
- **Aucun mot de passe, token ou donnée privée** récupérés
- **Usage légal** — audit de son propre PC uniquement
- Ne pas utiliser sur des systèmes sans autorisation

---

## Stack technique

- Python 3.10+
- psutil — informations système et processus
- subprocess — registre Windows et PowerShell
- socket — réseau
- JSON + HTML — génération de rapport

---

## Roadmap

- [ ] Export PDF
- [ ] Comparaison entre deux audits (diff)
- [ ] Détection de logiciels obsolètes
- [ ] Vérification des permissions de fichiers sensibles
- [ ] Mode silencieux (cron/planification)

---

*Projet éducatif — Portfolio Enzo ATTICOT*
