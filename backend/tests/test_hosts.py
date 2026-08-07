import pytest
from fastapi import HTTPException

from app.modules import hosts


@pytest.fixture(autouse=True)
def isolated_hosts_file(tmp_path, monkeypatch):
    path = tmp_path / "hosts"
    path.write_text("127.0.0.1\tlocalhost\n")
    monkeypatch.setattr(hosts, "HOSTS_PATH", path)
    return path


def test_sync_then_remove_round_trips(isolated_hosts_file):
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))
    assert "box.htb" in hosts.list_synced_hosts()["entries"]

    remaining = hosts.remove_entries(["box.htb"])

    assert remaining == {}
    assert "box.htb" not in isolated_hosts_file.read_text()
    assert "127.0.0.1\tlocalhost" in isolated_hosts_file.read_text()


def test_remove_entries_is_a_noop_for_unknown_hostname(isolated_hosts_file):
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))
    before = isolated_hosts_file.read_text()

    remaining = hosts.remove_entries(["someone-else.htb"])

    assert remaining == {"box.htb": "10.129.1.1"}
    assert isolated_hosts_file.read_text() == before


def test_resync_after_ip_reset_overwrites_stale_entry_instead_of_duplicating(
        isolated_hosts_file):
    hosts.sync_host(hosts.HostsSync(ip="10.129.1.1", hostname="box.htb"))
    hosts.sync_host(hosts.HostsSync(ip="10.129.2.2", hostname="box.htb"))

    entries = hosts.list_synced_hosts()["entries"]

    assert entries == {"box.htb": "10.129.2.2"}


def test_remove_host_rejects_symlinked_hosts_file(tmp_path, monkeypatch):
    real = tmp_path / "real-hosts"
    real.write_text(f"{hosts.MARKER_BEGIN}\n10.129.1.1\tbox.htb\n{hosts.MARKER_END}\n")
    link = tmp_path / "hosts-link"
    link.symlink_to(real)
    monkeypatch.setattr(hosts, "HOSTS_PATH", link)

    with pytest.raises(HTTPException):
        hosts.remove_entries(["box.htb"])
