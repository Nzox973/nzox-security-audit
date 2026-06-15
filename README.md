# Nzox Security Audit Tool

Outil d'audit Windows défensif en Python.
Analyse l'état de sécurité du PC et génère un rapport HTML.

**Auteur :** Enzo ATTICOT ([@Nzox973](https://github.com/Nzox973))
**Contexte :** Projet portfolio — Terminale NSI
**Licence :** MIT

> **Usage éthique :** cet outil est conçu pour auditer **votre propre machine**. Toute utilisation sur un système sans autorisation explicite est illégale. Aucune donnée n'est envoyée à l'extérieur.

---

## Ce que ce projet démontre

- Utilisation de `psutil` pour interroger les ressources système (processus, réseau, disque)
- Appels `subprocess` vers le registre Windows et PowerShell
- Génération de rapport HTML stylisé en Python pur
- Gestion des erreurs et des droits d'accès limités
- Séparation claire données locales / données publiées (`.gitignore` sur `reports/`)
- Adaptation aux contraintes d'encodage Windows (UTF-8 vs cp1252)

---

## Fonctionnalités

| Vérification | Description |
|---|---|
| Informations système | OS, version, architecture |
| Espace disque | Utilisation par partition, alerte si > 75% |
| Processus lourds | Top 10 par RAM (CPU + mémoire) |
| Démarrage | Programmes au démarrage via registre Windows |
| Ports ouverts | Ports en écoute + processus associés |
| Windows Defender | État protection temps réel et antivirus |
| Mises à jour | Date de dernière vérification Windows Update |
| Interfaces réseau | Interfaces actives + adresses IP |

---

## Installation

```bash
pip install psutil
```

Python 3.9+ requis.

---

## Utilisation

```bash
# Rapport HTML (défaut)
python audit.py

# Rapport Markdown
python audit.py --md

# Les deux formats
python audit.py --html --md
```

Les rapports sont sauvegardés dans `reports/` (exclu de git — ne jamais publier un rapport réel).

---

## Exemple de sortie console

```
[NZOX] Security Audit Tool -- demarrage...

  → System Info...
  → Disk Space...
  → Top Processes...
  → Startup Programs...
  → Open Ports...
  → Defender...
  → Windows Updates...
  → Network Interfaces...

[OK] Rapport HTML -> reports/audit_20260614_203702.html

==================================================
Audit termine -- 0 point(s) a verifier sur 8 sections.
==================================================
```

---

## Limitations

- Windows uniquement (utilise le registre et PowerShell)
- Certaines vérifications nécessitent des droits administrateur
- Les ports réseau ne sont pas tous visibles sans admin
- Aucune détection de malware — ce n'est pas un antivirus
- Ne surveille pas en temps réel — c'est un snapshot ponctuel
- Ne couvre pas Linux, macOS ou les environnements cloud

---

## Améliorations futures

- [ ] Comparaison entre deux audits (diff avant/après)
- [ ] Détection de logiciels obsolètes (version vs dernière connue)
- [ ] Mode planifié / cron Windows
- [ ] Export PDF
- [ ] Vérification des permissions sur fichiers sensibles
- [ ] Support Linux (bases)

---

## Stack technique

| Technologie | Usage |
|---|---|
| Python 3.9+ | Langage principal |
| psutil | Processus, réseau, disque |
| subprocess | Registre Windows, PowerShell |
| json | Parsing des résultats PowerShell |
| HTML/CSS inline | Génération du rapport |

---

## Sécurité

- Aucune donnée envoyée à l'extérieur
- Aucun fichier modifié ou supprimé
- Aucun mot de passe, token ou donnée privée collecté
- Les rapports générés (dans `reports/`) sont exclus du dépôt Git
- Usage légal uniquement : audit de sa propre machine

---

*Projet éducatif — Enzo ATTICOT — github.com/Nzox973*
