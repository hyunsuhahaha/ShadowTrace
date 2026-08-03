from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.modules import privesc_server as server


@pytest.fixture(autouse=True)
def isolated_toolsets(tmp_path, monkeypatch):
    peass = tmp_path / "peass"
    pspy = tmp_path / "pspy"
    stage = tmp_path / "stage"
    monkeypatch.setattr(server, "PEASS_DIR", peass)
    monkeypatch.setattr(server, "PSPY_DIR", pspy)
    monkeypatch.setattr(server, "TOOLSETS", {"peass": peass, "pspy": pspy})
    monkeypatch.setattr(server, "STAGE_DIR", stage)
    monkeypatch.setattr(server, "_process", None)
    monkeypatch.setattr(server, "_port", None)
    return peass, pspy, stage


def test_available_reflects_which_toolsets_are_installed(isolated_toolsets):
    peass, pspy, _ = isolated_toolsets
    assert server._available() == {"peass": False, "pspy": False}
    peass.mkdir()
    assert server._available() == {"peass": True, "pspy": False}
    pspy.mkdir()
    assert server._available() == {"peass": True, "pspy": True}


def test_stage_symlinks_only_installed_toolsets_and_prunes_stale_links(isolated_toolsets):
    peass, pspy, stage = isolated_toolsets
    peass.mkdir()
    (peass / "linpeas").mkdir()
    (peass / "linpeas" / "linpeas.sh").write_text("#!/bin/sh\n")

    available = server._stage()
    assert available == {"peass": True, "pspy": False}
    assert (stage / "peass").is_symlink()
    assert (stage / "peass" / "linpeas" / "linpeas.sh").is_file()
    assert not (stage / "pspy").exists()

    # pspy shows up after being installed and a rebuild
    pspy.mkdir()
    (pspy / "pspy64").write_bytes(b"fake-binary")
    available = server._stage()
    assert available == {"peass": True, "pspy": True}
    assert (stage / "pspy" / "pspy64").is_file()

    # and disappears again if uninstalled, without leaving a broken symlink
    import shutil
    shutil.rmtree(pspy)
    available = server._stage()
    assert available == {"peass": True, "pspy": False}
    assert not (stage / "pspy").exists()


def test_start_fails_when_neither_toolset_is_installed(isolated_toolsets):
    with pytest.raises(HTTPException) as exc:
        server.start_privesc_server()
    assert exc.value.status_code == 409


def test_start_succeeds_with_only_pspy_installed(isolated_toolsets, monkeypatch):
    _, pspy, stage = isolated_toolsets
    pspy.mkdir()
    (pspy / "pspy64").write_bytes(b"fake-binary")
    monkeypatch.setattr(server, "vpn_status", lambda: {"tun0": "10.10.14.5/24"})
    monkeypatch.setattr(server, "_free_port", lambda host: 55123)

    captured = {}

    def fake_popen(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(poll=lambda: None, pid=4242)

    monkeypatch.setattr(server.subprocess, "Popen", fake_popen)
    result = server.start_privesc_server()
    assert result["running"] is True
    assert result["available"] == {"peass": False, "pspy": True}
    assert result["base_url"].startswith("http://10.10.14.5:")
    assert captured["argv"][:4] == ["/usr/bin/python3", "-m", "http.server", str(result["port"])]
    assert captured["argv"][-2:] == ["--directory", str(stage)]


def test_status_reports_available_toolsets_even_when_stopped(isolated_toolsets):
    peass, _, _ = isolated_toolsets
    peass.mkdir()
    result = server.privesc_server_status()
    assert result == {"running": False, "available": {"peass": True, "pspy": False}}
