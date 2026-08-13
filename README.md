# Nzox Security Audit Tool

[![CI](https://github.com/Nzox973/nzox-security-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/Nzox973/nzox-security-audit/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Outil pédagogique d'audit défensif pour Windows. Il observe l'état local de la machine et génère un rapport HTML ou Markdown sans envoyer de données sur Internet et sans modifier la configuration du PC.

> Utiliser uniquement sur une machine qui vous appartient ou pour laquelle vous avez une autorisation explicite. L'outil n'est ni un antivirus ni une preuve de conformité.

## Contrôles réalisés

| Section | Observation |
|---|---|
| Système | version de Windows, architecture et version Python |
| Disques | capacité utilisée et seuils d'alerte |
| Processus | dix processus consommant le plus de mémoire |
| Démarrage | entrées des clés `Run` utilisateur et machine |
| Réseau | ports locaux en écoute et processus associés |
| Defender | service, antivirus et protection en temps réel |
| Windows Update | date de la dernière recherche connue |
| Interfaces | interfaces réseau actives |

## Confidentialité par défaut

Le mode normal réduit les informations susceptibles d'identifier la machine :

- nom du PC masqué ;
- adresses IP masquées ;
- PID masqués ;
- commandes complètes de démarrage masquées ;
- rapports enregistrés uniquement dans `reports/`, dossier exclu de Git.

Le rapport contient tout de même des informations locales utiles — noms de processus, ports, logiciels au démarrage, état de sécurité et capacité des disques. Il doit donc rester privé. Relire et expurger un rapport avant tout partage.

Le mode `--details` ajoute volontairement le nom du PC, les IP, les PID et les commandes de démarrage. Il est réservé au diagnostic local et son rapport ne doit pas être publié.

Les fichiers dans `examples/` sont des rapports **fictifs** du mode détaillé, conservés pour montrer la différence avec la sortie minimisée par défaut.

## Installation

Prérequis : Windows et Python 3.11 ou supérieur.

```bash
git clone https://github.com/Nzox973/nzox-security-audit.git
cd nzox-security-audit
python -m venv .venv
```

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Utilisation

```bash
# Rapport HTML minimisé — comportement par défaut
python audit.py

# Rapport Markdown minimisé
python audit.py --md

# Les deux formats
python audit.py --html --md

# Diagnostic local détaillé — ne pas publier le rapport
python audit.py --html --details
```

Certaines observations, notamment les connexions réseau ou l'état Defender, peuvent nécessiter des droits élevés. L'outil signale les accès refusés au lieu de contourner les permissions.

## Sécurité du générateur de rapport

- toutes les valeurs dynamiques sont échappées avant insertion dans le HTML ;
- les caractères pouvant fermer une zone de code Markdown sont neutralisés ;
- aucune donnée n'est transmise à un serveur ;
- aucun fichier système, service ou paramètre Windows n'est modifié ;
- une erreur dans une section n'interrompt pas les autres contrôles.

## Tests

```bash
pip install -r requirements-dev.txt
ruff check audit.py tests
pytest -q
```

La CI Windows vérifie l'échappement HTML, la neutralisation Markdown et l'absence du nom de machine dans le rapport par défaut.

## Limites

- Windows uniquement ;
- photographie ponctuelle, sans surveillance temps réel ;
- pas de détection de malware ;
- pas d'analyse des versions logicielles ni des correctifs tiers ;
- résultat partiel lorsque les permissions Windows limitent l'accès ;
- un statut « OK » signifie seulement qu'aucune alerte définie par cet outil n'a été trouvée.

## Auteur

**Enzo ATTICOT** — [@Nzox973](https://github.com/Nzox973)

Projet éducatif sous licence MIT.
