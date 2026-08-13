from pathlib import Path
from types import SimpleNamespace

import audit


def test_html_report_escapes_dynamic_content(tmp_path: Path):
    output = tmp_path / "report.html"
    sections = [
        {
            "title": "<script>alert(1)</script>",
            "items": ["<img src=x onerror=alert(2)>", "safe"],
            "status": "warn",
        }
    ]

    audit.generate_html_report(sections, str(output))

    content = output.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in content
    assert "&lt;img src=x onerror=alert(2)&gt;" in content
    assert 'style="' not in content


def test_default_system_report_omits_hostname(monkeypatch):
    monkeypatch.setattr(audit.platform, "node", lambda: "PRIVATE-HOST")

    minimized = audit.check_system_info()
    detailed = audit.check_system_info(detailed=True)

    assert all("PRIVATE-HOST" not in item for item in minimized["items"])
    assert any("PRIVATE-HOST" in item for item in detailed["items"])


def test_markdown_report_neutralizes_code_fence_breakout(tmp_path: Path):
    output = tmp_path / "report.md"
    sections = [{"title": "Test", "items": ["value ` injected"], "status": "ok"}]

    audit.generate_md_report(sections, str(output))

    content = output.read_text(encoding="utf-8")
    assert "value ` injected" not in content
    assert "value ˋ injected" in content


def test_default_network_report_omits_ip_addresses(monkeypatch):
    monkeypatch.setattr(
        audit.psutil,
        "net_if_stats",
        lambda: {"Wi-Fi": SimpleNamespace(isup=True)},
    )
    monkeypatch.setattr(
        audit.psutil,
        "net_if_addrs",
        lambda: {"Wi-Fi": [SimpleNamespace(address="192.0.2.42")]},
    )

    minimized = audit.check_network_interfaces()
    detailed = audit.check_network_interfaces(detailed=True)

    assert all("192.0.2.42" not in item for item in minimized["items"])
    assert any("192.0.2.42" in item for item in detailed["items"])


def test_default_process_report_omits_pid(monkeypatch):
    process = SimpleNamespace(
        info={
            "pid": 4242,
            "name": "example.exe",
            "cpu_percent": 1.0,
            "memory_info": SimpleNamespace(rss=100 * 1024**2),
        }
    )
    monkeypatch.setattr(audit.psutil, "process_iter", lambda _: [process])

    minimized = audit.check_top_processes()
    detailed = audit.check_top_processes(detailed=True)

    assert all("4242" not in item for item in minimized["items"])
    assert any("4242" in item for item in detailed["items"])


def test_default_startup_report_omits_command(monkeypatch):
    result = SimpleNamespace(
        returncode=0,
        stdout="Example REG_SZ C:\\Users\\Private\\secret.exe --token value",
    )
    monkeypatch.setattr(audit.subprocess, "run", lambda *args, **kwargs: result)

    minimized = audit.check_startup_programs()
    detailed = audit.check_startup_programs(detailed=True)

    assert all("secret.exe" not in item for item in minimized["items"])
    assert any("secret.exe" in item for item in detailed["items"])
