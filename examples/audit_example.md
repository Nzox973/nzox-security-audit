# 🔐 Nzox Security Audit Tool
**Rapport généré le** : 2026-06-14 20:37:02  
**Machine** : DESKTOP-EXEMPLE

> **Rapport anonymisé** — Cet exemple illustre le format de sortie de l'outil.
> Les données système, noms de processus, adresses IP et ports sont fictifs ou génériques.

---

## ✅ Informations système

- `OS : Windows 11 Home (10.0.22621)`
- `Nom machine : DESKTOP-EXEMPLE`
- `Architecture : AMD64`
- `Python : 3.11.4`
- `Heure audit : 2026-06-14 20:37:02`

## ⚠️ Espace disque

- `✅ C:\ — 87.3 Go / 237.1 Go (36.8%)`
- `⚠️ Attention D:\ — 178.4 Go / 238.5 Go (74.8%)`
- `✅ E:\ — 12.1 Go / 465.8 Go (2.6%)`

## ✅ Processus les plus lourds (CPU + RAM)

- `  PID   1234 | chrome.exe                     | CPU   3.2% | RAM   512.4 Mo`
- `  PID   5678 | Code.exe                       | CPU   1.8% | RAM   387.1 Mo`
- `  PID   9012 | MsMpEng.exe                    | CPU   0.9% | RAM   201.7 Mo`
- `  PID   3456 | python.exe                     | CPU   0.4% | RAM   148.3 Mo`
- `  PID   7890 | explorer.exe                   | CPU   0.2% | RAM   112.8 Mo`

## ✅ Programmes au démarrage (registre)

- `  [HKLM] SecurityHealth → %windir%\system32\SecurityHealthSystray.exe`
- `  [HKCU] OneDrive → C:\Users\utilisateur\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
- `  [HKCU] Discord → C:\Users\utilisateur\AppData\Local\Discord\Update.exe --processStart Discord.exe`

## ✅ Ports réseau ouverts (écoute locale)

- `  Port   135 | 0.0.0.0:135            | svchost.exe (PID 832)`
- `  Port   445 | 0.0.0.0:445            | System (PID 4)`
- `  Port  1900 | 0.0.0.0:1900           | svchost.exe (PID 2340)`
- `  Port  5040 | 0.0.0.0:5040           | svchost.exe (PID 1876)`
- `  Port  8080 | 127.0.0.1:8080         | python.exe (PID 3456)`

## ✅ Windows Defender / Antivirus

- `  Service AM actif       : ✅ Oui`
- `  Protection temps réel  : ✅ Oui`
- `  Antivirus actif        : ✅ Oui`

## ⚠️ Mises à jour Windows (dernière vérification)

- `  Dernière recherche MAJ : 2026-05-28T09:14:33Z`
- `  ℹ️ Dernière vérification il y a plus de 14 jours — vérifier dans Paramètres > Windows Update`

## ✅ Interfaces réseau actives

- `  ✅ Ethernet                        | 192.168.1.42`
- `  ✅ Wi-Fi                            | 192.168.1.43`
- `  ✅ Loopback Pseudo-Interface 1      | 127.0.0.1`

---
*Nzox Security Audit Tool — Usage défensif et éducatif uniquement*
