"""
Nzox Security Audit Tool
Audit défensif Windows — génère un rapport HTML/Markdown
Usage : python audit.py [--html] [--md] [--details]
"""

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
from html import escape

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

REPORT_DIR = os.path.join(os.path.dirname(__file__), "reports")


def now_local() -> datetime.datetime:
    """Retourne une date consciente du fuseau local."""
    return datetime.datetime.now(datetime.UTC).astimezone()


def section(title: str) -> dict:
    return {"title": title, "items": [], "status": "ok"}


def check_system_info(*, detailed: bool = False) -> dict:
    s = section("Informations système")
    s["items"] = [
        f"OS : {platform.system()} {platform.release()} ({platform.version()})",
        f"Architecture : {platform.machine()}",
        f"Python : {platform.python_version()}",
        f"Heure audit : {now_local().strftime('%Y-%m-%d %H:%M:%S %z')}",
    ]
    if detailed:
        s["items"].insert(1, f"Nom machine : {platform.node()}")
    return s


def check_disk_space(*, detailed: bool = False) -> dict:
    s = section("Espace disque")
    if not HAS_PSUTIL:
        s["items"].append("psutil non disponible — pip install psutil")
        s["status"] = "warn"
        return s

    for partition in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            pct = usage.percent
            used_gb = usage.used / (1024 ** 3)
            total_gb = usage.total / (1024 ** 3)
            flag = "⚠️ CRITIQUE" if pct > 90 else ("⚠️ Attention" if pct > 75 else "✅")
            s["items"].append(
                f"{flag} {partition.device} — {used_gb:.1f} Go / {total_gb:.1f} Go ({pct}%)"
            )
            if pct > 90:
                s["status"] = "warn"
        except PermissionError:
            s["items"].append(f"⛔ {partition.device} — accès refusé")
    return s


def check_top_processes(*, detailed: bool = False) -> dict:
    s = section("Processus les plus lourds (CPU + RAM)")
    if not HAS_PSUTIL:
        s["items"].append("psutil non disponible — pip install psutil")
        s["status"] = "warn"
        return s

    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info']):
        try:
            info = proc.info
            mem_mb = info['memory_info'].rss / (1024 ** 2)
            procs.append((info['name'], info['cpu_percent'], mem_mb, info['pid']))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    procs.sort(key=lambda x: x[2], reverse=True)
    for name, cpu, mem, pid in procs[:10]:
        prefix = f"PID {pid:6d} | " if detailed else ""
        s["items"].append(f"  {prefix}{name:<30} | CPU {cpu:5.1f}% | RAM {mem:7.1f} Mo")
    return s


def check_startup_programs(*, detailed: bool = False) -> dict:
    s = section("Programmes au démarrage (registre)")
    keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    ]
    found = []
    for key in keys:
        try:
            result = subprocess.run(
                ["reg", "query", key],
                capture_output=True, text=True, timeout=5, check=False
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.splitlines() if l.strip() and "REG_" in l]
                for line in lines:
                    parts = line.split(None, 2)
                    if len(parts) >= 3:
                        entry = f"  [{key.split(chr(92))[0]}] {parts[0]}"
                        if detailed:
                            entry += f" → {parts[2][:80]}"
                        found.append(entry)
        except (OSError, subprocess.SubprocessError) as e:
            s["items"].append(f"Erreur lecture registre : {e}")

    if found:
        s["items"] = found
    else:
        s["items"].append("Aucun programme de démarrage détecté ou accès limité.")
    return s


def check_open_ports(*, detailed: bool = False) -> dict:
    s = section("Ports réseau ouverts (écoute locale)")
    if not HAS_PSUTIL:
        s["items"].append("psutil non disponible — pip install psutil")
        s["status"] = "warn"
        return s

    connections = []
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'LISTEN':
                addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                pid = conn.pid
                name = "?"
                if pid:
                    try:
                        name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        name = "accès limité"
                connections.append((conn.laddr.port, addr, conn.laddr.ip, name, pid or 0))
    except psutil.AccessDenied:
        s["items"].append("⛔ Accès refusé — relancer en administrateur pour voir tous les ports")
        s["status"] = "warn"
        return s

    connections.sort(key=lambda x: x[0])
    for port, addr, ip, name, pid in connections:
        if detailed:
            endpoint = addr
            process = f"{name} (PID {pid})"
        else:
            endpoint = "toutes interfaces" if ip in {"0.0.0.0", "::"} else "interface ciblée"
            process = name
        s["items"].append(f"  Port {port:5d} | {endpoint:<22} | {process}")

    if not connections:
        s["items"].append("Aucun port en écoute détecté.")
    return s


def check_defender(*, detailed: bool = False) -> dict:
    s = section("Windows Defender / Antivirus")
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-MpComputerStatus | Select-Object -Property AMServiceEnabled,RealTimeProtectionEnabled,AntivirusEnabled | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            s["items"].append(f"  Service AM actif       : {'✅ Oui' if data.get('AMServiceEnabled') else '❌ NON'}")
            s["items"].append(f"  Protection temps réel  : {'✅ Oui' if data.get('RealTimeProtectionEnabled') else '❌ NON'}")
            s["items"].append(f"  Antivirus actif        : {'✅ Oui' if data.get('AntivirusEnabled') else '❌ NON'}")
            if not data.get('RealTimeProtectionEnabled'):
                s["status"] = "warn"
        else:
            s["items"].append("Impossible de récupérer le statut — PowerShell non disponible ou droits insuffisants")
            s["status"] = "warn"
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, TypeError) as e:
        s["items"].append(f"Erreur : {e}")
        s["status"] = "warn"
    return s


def check_windows_updates(*, detailed: bool = False) -> dict:
    s = section("Mises à jour Windows (dernière vérification)")
    try:
        result = subprocess.run(
            ["powershell", "-Command",
             "(New-Object -ComObject Microsoft.Update.AutoUpdate).Results | Select-Object -Property LastSearchSuccessDate | ConvertTo-Json"],
            capture_output=True, text=True, timeout=10, check=False
        )
        if result.returncode == 0 and result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                date = data.get("LastSearchSuccessDate", "?")
                s["items"].append(f"  Dernière recherche MAJ : {date}")
            except (json.JSONDecodeError, AttributeError, TypeError):
                s["items"].append("  Données MAJ disponibles mais format inattendu")
        else:
            s["items"].append("  Impossible de récupérer les MAJ via COM — vérifier manuellement dans Paramètres > Windows Update")
    except (OSError, subprocess.SubprocessError) as e:
        s["items"].append(f"  Erreur : {e}")
    return s


def check_network_interfaces(*, detailed: bool = False) -> dict:
    s = section("Interfaces réseau actives")
    if not HAS_PSUTIL:
        s["items"].append("psutil non disponible")
        return s

    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface, stat in stats.items():
        if stat.isup:
            ips = [a.address for a in addrs.get(iface, []) if ':' not in a.address]
            if detailed:
                ip_str = ', '.join(ips) if ips else 'pas d\'IP v4'
                s["items"].append(f"  ✅ {iface:<30} | {ip_str}")
            else:
                s["items"].append(f"  ✅ {iface}")
    return s


def generate_html_report(sections: list[dict], out_path: str, *, detailed: bool = False):
    now = now_local().strftime("%Y-%m-%d %H:%M:%S %z")
    warn_count = sum(1 for s in sections if s["status"] == "warn")

    rows = ""
    for sec in sections:
        status_class = "warn" if sec["status"] == "warn" else "ok"
        badge = "⚠️ Attention" if sec["status"] == "warn" else "✅ OK"
        items_html = "\n".join(
            f"<li><code>{escape(str(item))}</code></li>" for item in sec["items"]
        )
        rows += f"""
        <div class="card {'warn' if sec['status'] == 'warn' else ''}">
          <div class="card-header">
            <h2>{escape(str(sec['title']))}</h2>
            <span class="badge {status_class}">{badge}</span>
          </div>
          <ul>{items_html}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<title>Nzox Security Audit — {escape(now)}</title>
<style>
  body {{ font-family: 'Segoe UI', monospace; background: #0a0a0f; color: #e8e8f0; margin: 0; padding: 2rem; }}
  .header {{ border-bottom: 2px solid #6c63ff; padding-bottom: 1rem; margin-bottom: 2rem; }}
  h1 {{ font-size: 1.8rem; color: #6c63ff; }}
  .meta {{ color: #9090a8; font-size: 0.85rem; margin-top: 0.3rem; }}
  .summary {{ display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }}
  .chip {{ padding: 0.4rem 1rem; border-radius: 20px; font-size: 0.8rem; border: 1px solid; }}
  .chip.ok {{ border-color: #00d4aa; color: #00d4aa; }}
  .chip.warn {{ border-color: #ff6b6b; color: #ff6b6b; }}
  .card {{ background: #141420; border: 1px solid #2a2a40; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  .card.warn {{ border-color: rgba(255,107,107,0.4); }}
  .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }}
  h2 {{ font-size: 1rem; color: #e8e8f0; }}
  .badge {{ font-size: 0.8rem; }}
  .badge.ok {{ color: #00d4aa; }}
  .badge.warn {{ color: #ff6b6b; }}
  ul {{ list-style: none; padding: 0; }}
  li {{ margin: 0.3rem 0; }}
  code {{ font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; color: #9090a8; white-space: pre-wrap; }}
  footer {{ text-align: center; color: #9090a8; font-size: 0.8rem; margin-top: 3rem; }}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 Nzox Security Audit Tool</h1>
  <p class="meta">Rapport généré le {escape(now)} — Mode : {'détaillé' if detailed else 'minimisé'}</p>
</div>
<div class="summary">
  <div class="chip ok">✅ {len(sections) - warn_count} sections OK</div>
  <div class="chip warn">⚠️ {warn_count} point(s) à vérifier</div>
</div>
{rows}
<footer>Nzox Security Audit Tool — Usage défensif et éducatif uniquement — github.com/Nzox973</footer>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[OK] Rapport HTML -> {out_path}")


def generate_md_report(sections: list[dict], out_path: str, *, detailed: bool = False):
    now = now_local().strftime("%Y-%m-%d %H:%M:%S %z")
    lines = [
        "# 🔐 Nzox Security Audit Tool",
        f"**Rapport généré le** : {now}  ",
        f"**Mode** : {'détaillé' if detailed else 'minimisé'}",
        "",
        "---",
        "",
    ]
    for sec in sections:
        badge = "⚠️" if sec["status"] == "warn" else "✅"
        safe_title = str(sec["title"]).replace("\n", " ")
        lines.append(f"## {badge} {safe_title}")
        lines.append("")
        for item in sec["items"]:
            safe_item = str(item).replace("`", "ˋ").replace("\n", " ")
            lines.append(f"- `{safe_item}`")
        lines.append("")

    lines.append("---")
    lines.append("*Nzox Security Audit Tool — Usage défensif et éducatif uniquement*")

    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[OK] Rapport Markdown -> {out_path}")


def run_audit(html: bool = True, md: bool = False, detailed: bool = False):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print("\n[NZOX] Security Audit Tool -- demarrage...\n")

    if not HAS_PSUTIL:
        print("[WARN] psutil non trouve. Certaines verifications seront limitees.")
        print("       Installer : pip install psutil\n")

    checks = [
        check_system_info,
        check_disk_space,
        check_top_processes,
        check_startup_programs,
        check_open_ports,
        check_defender,
        check_windows_updates,
        check_network_interfaces,
    ]

    sections = []
    for check in checks:
        print(f"  → {check.__name__.replace('check_', '').replace('_', ' ').title()}...")
        try:
            sections.append(check(detailed=detailed))
        except Exception as e:  # noqa: BLE001 - une section défaillante ne doit pas arrêter l'audit
            sections.append({
                "title": check.__name__,
                "items": [f"Erreur inattendue : {e}"],
                "status": "warn"
            })

    os.makedirs(REPORT_DIR, exist_ok=True)
    stamp = now_local().strftime("%Y%m%d_%H%M%S")

    if html:
        generate_html_report(
            sections,
            os.path.join(REPORT_DIR, f"audit_{stamp}.html"),
            detailed=detailed,
        )
    if md:
        generate_md_report(
            sections,
            os.path.join(REPORT_DIR, f"audit_{stamp}.md"),
            detailed=detailed,
        )
    if not html and not md:
        generate_html_report(
            sections,
            os.path.join(REPORT_DIR, f"audit_{stamp}.html"),
            detailed=detailed,
        )

    warn_count = sum(1 for s in sections if s["status"] == "warn")
    print(f"\n{'='*50}")
    print(f"Audit termine -- {warn_count} point(s) a verifier sur {len(sections)} sections.")
    print(f"Rapport sauvegarde dans : {REPORT_DIR}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Audit défensif local pour Windows")
    parser.add_argument("--html", action="store_true", help="générer un rapport HTML")
    parser.add_argument("--md", action="store_true", help="générer un rapport Markdown")
    parser.add_argument(
        "--details",
        action="store_true",
        help="inclure les IP, PID, commandes de démarrage et le nom du PC",
    )
    args = parser.parse_args()
    run_audit(
        html=args.html or not args.md,
        md=args.md,
        detailed=args.details,
    )
