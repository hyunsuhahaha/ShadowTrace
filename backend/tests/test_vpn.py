import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.modules import vpn
from app.modules.vpn import validate_ovpn


def test_valid_client_ovpn_is_accepted():
    text = validate_ovpn(
        b"client\n"
        b"dev tun\n"
        b"proto udp\n"
        b"remote vpn.example.test 1194\n"
        b"<ca>\ncertificate\n</ca>\n"
    )
    assert "remote vpn.example.test 1194" in text


@pytest.mark.parametrize(
    "directive",
    ["up", "down", "route-up", "auth-user-pass-verify", "script-security"],
)
def test_ovpn_rejects_command_execution_directives(directive):
    config = f"client\nremote vpn.example.test 1194\n{directive} /tmp/run\n".encode()
    with pytest.raises(HTTPException) as error:
        validate_ovpn(config)
    assert error.value.status_code == 400


def test_ovpn_requires_client_and_remote():
    with pytest.raises(HTTPException):
        validate_ovpn(b"dev tun\nproto udp\n")


def test_ovpn_rejects_external_root_readable_files():
    with pytest.raises(HTTPException):
        validate_ovpn(
            b"client\nremote vpn.example.test\nca /etc/shadow\n")


def vpn_paths(tmp_path, monkeypatch):
    folder = tmp_path / "vpn"
    monkeypatch.setattr(vpn, "VPN_DIR", folder)
    monkeypatch.setattr(vpn, "CONFIG_PATH", folder / "selected.ovpn")
    monkeypatch.setattr(vpn, "UUID_FILE", folder / "active-connection")
    return folder


def upload(name="fixture.ovpn"):
    async def read(_):
        return b"client\nremote vpn.example.test\n<ca>\nfixture\n</ca>\n"
    return SimpleNamespace(filename=name, read=read)


def test_prepare_requires_plain_filename_and_returns_review(
        tmp_path, monkeypatch):
    vpn_paths(tmp_path, monkeypatch)
    with pytest.raises(HTTPException):
        asyncio.run(vpn.prepare_vpn(upload("../fixture.ovpn")))
    review = asyncio.run(vpn.prepare_vpn(upload()))
    assert review["file_name"] == "fixture.ovpn"
    assert len(review["sha256"]) == 64
    assert review["profile_name"].startswith("oscp-workspace-")
    assert review["actions"] == [
        "NetworkManager profile import", "profile name set",
        "VPN connection up"]
    assert vpn.CONFIG_PATH.is_file()
    assert vpn.CONFIG_PATH.stat().st_mode & 0o777 == 0o660


def test_approved_connect_uses_fixed_nmcli_argv_once(
        tmp_path, monkeypatch):
    vpn_paths(tmp_path, monkeypatch)
    review = asyncio.run(vpn.prepare_vpn(upload()))
    connection_uuid = "12345678-1234-1234-1234-123456789abc"
    calls = []

    def run(argv, timeout=30):
        calls.append(argv)
        output = f"Connection 'fixture' ({connection_uuid})\n" if (
            argv[1:3] == ["connection", "import"]) else ""
        return {
            "action": argv[2], "argv": argv, "stdout": output,
            "stderr": "", "exit_code": 0,
        }

    monkeypatch.setattr(vpn, "_run", run)
    monkeypatch.setattr(vpn, "vpn_status", lambda: {"connected": True})
    result = vpn.connect_vpn(vpn.VpnApproval(
        approval_token=review["approval_token"]))
    assert [call[1:3] for call in calls] == [
        ["connection", "import"], ["connection", "modify"],
        ["connection", "up"]]
    modify = calls[1]
    assert modify[modify.index("ipv4.never-default") + 1] == "yes"
    assert modify[modify.index("ipv6.never-default") + 1] == "yes"
    assert all(call[0] == "/usr/bin/nmcli" for call in calls)
    assert [step["exit_code"] for step in result["operations"]] == [0, 0, 0]
    with pytest.raises(HTTPException):
        vpn.connect_vpn(vpn.VpnApproval(
            approval_token=review["approval_token"]))


def test_approval_rejects_changed_or_symlinked_file(
        tmp_path, monkeypatch):
    folder = vpn_paths(tmp_path, monkeypatch)
    review = asyncio.run(vpn.prepare_vpn(upload()))
    vpn.CONFIG_PATH.write_text("changed")
    with pytest.raises(HTTPException):
        vpn.connect_vpn(vpn.VpnApproval(
            approval_token=review["approval_token"]))
    vpn.CONFIG_PATH.unlink()
    outside = tmp_path / "outside.ovpn"
    outside.write_text("client\nremote vpn.example.test\n")
    vpn.CONFIG_PATH.symlink_to(outside)
    with pytest.raises(HTTPException):
        vpn._config_file()


def test_tun0_link_type_detects_tun_devices_masscan_cannot_use(monkeypatch):
    monkeypatch.setattr(vpn, "_run", lambda argv, timeout=2: {
        "exit_code": 0,
        "stdout": (
            "4: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500\n"
            "    link/none  promiscuity 0\n"
            "    tun type tun pi off vnet_hdr off persist off\n"
        ),
    })
    assert vpn._tun0_link_type() == "tun"


def test_tun0_link_type_detects_ethernet_capable_tap_devices(monkeypatch):
    monkeypatch.setattr(vpn, "_run", lambda argv, timeout=2: {
        "exit_code": 0,
        "stdout": (
            "4: tun0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
            "    link/ether 00:ff:11:22:33:44 brd ff:ff:ff:ff:ff:ff\n"
            "    tun type tap\n"
        ),
    })
    assert vpn._tun0_link_type() == "tap"


def test_tun0_link_type_is_blank_when_the_interface_does_not_exist(monkeypatch):
    monkeypatch.setattr(vpn, "_run", lambda argv, timeout=2: {
        "exit_code": 1, "stdout": "", "stderr": "Device \"tun0\" does not exist.",
    })
    assert vpn._tun0_link_type() == ""


def test_vpn_status_reports_link_type(monkeypatch):
    monkeypatch.setattr(vpn, "_status_operation", lambda: {
        "action": "status", "argv": [], "stdout": "", "stderr": "", "exit_code": 0,
    })
    monkeypatch.setattr(vpn, "_tun0_link_type", lambda: "tun")
    monkeypatch.setattr(vpn, "_run", lambda argv, timeout=2: {
        "action": "status", "argv": argv, "stdout": "", "stderr": "", "exit_code": 0,
    })
    status = vpn.vpn_status()
    assert status["link_type"] == "tun"


def test_set_target_dns_rejects_invalid_ip(tmp_path, monkeypatch):
    vpn_paths(tmp_path, monkeypatch)
    with pytest.raises(HTTPException) as error:
        vpn.set_target_dns(vpn.TargetDns(ip="not-an-ip"))
    assert error.value.status_code == 400


def test_set_target_dns_requires_an_app_managed_connection(tmp_path, monkeypatch):
    vpn_paths(tmp_path, monkeypatch)
    with pytest.raises(HTTPException) as error:
        vpn.set_target_dns(vpn.TargetDns(ip="10.10.10.161"))
    assert error.value.status_code == 409


def test_set_target_dns_modifies_and_reapplies_the_vpn_connection(
        tmp_path, monkeypatch):
    folder = vpn_paths(tmp_path, monkeypatch)
    connection_uuid = "12345678-1234-1234-1234-123456789abc"
    folder.mkdir(parents=True, exist_ok=True)
    vpn.UUID_FILE.write_text(connection_uuid)
    calls = []

    def run(argv, timeout=30):
        calls.append(argv)
        return {"action": argv[1], "argv": argv, "stdout": "", "stderr": "",
                "exit_code": 0}

    monkeypatch.setattr(vpn, "_run", run)
    monkeypatch.setattr(vpn, "vpn_status", lambda: {"connected": True})
    result = vpn.set_target_dns(vpn.TargetDns(ip="10.10.10.161"))
    assert calls[0] == [
        vpn.NMCLI, "connection", "modify", "uuid", connection_uuid,
        "ipv4.dns", "10.10.10.161", "ipv4.dns-priority", "-1"]
    assert calls[1] == [vpn.NMCLI, "device", "reapply", "tun0"]
    assert [step["exit_code"] for step in result["operations"]] == [0, 0]


def test_clear_target_dns_resets_the_vpn_connection(tmp_path, monkeypatch):
    folder = vpn_paths(tmp_path, monkeypatch)
    connection_uuid = "12345678-1234-1234-1234-123456789abc"
    folder.mkdir(parents=True, exist_ok=True)
    vpn.UUID_FILE.write_text(connection_uuid)
    calls = []

    def run(argv, timeout=30):
        calls.append(argv)
        return {"action": argv[1], "argv": argv, "stdout": "", "stderr": "",
                "exit_code": 0}

    monkeypatch.setattr(vpn, "_run", run)
    monkeypatch.setattr(vpn, "vpn_status", lambda: {"connected": True})
    vpn.clear_target_dns()
    assert calls[0] == [
        vpn.NMCLI, "connection", "modify", "uuid", connection_uuid,
        "ipv4.dns", "", "ipv4.dns-priority", "0"]
    assert calls[1] == [vpn.NMCLI, "device", "reapply", "tun0"]


def test_vpn_status_reports_the_currently_applied_target_dns(
        tmp_path, monkeypatch):
    folder = vpn_paths(tmp_path, monkeypatch)
    connection_uuid = "12345678-1234-1234-1234-123456789abc"
    folder.mkdir(parents=True, exist_ok=True)
    vpn.UUID_FILE.write_text(connection_uuid)
    monkeypatch.setattr(vpn, "_status_operation", lambda: {
        "action": "status", "argv": [], "stdout": "", "stderr": "", "exit_code": 0,
    })
    monkeypatch.setattr(vpn, "_tun0_link_type", lambda: "tun")

    def run(argv, timeout=2):
        if argv[1:4] == ["-g", "ipv4.dns", "connection"]:
            return {"exit_code": 0, "stdout": "10.10.10.161\n"}
        return {"action": "status", "argv": argv, "stdout": "", "stderr": "",
                "exit_code": 0}

    monkeypatch.setattr(vpn, "_run", run)
    assert vpn.vpn_status()["target_dns"] == "10.10.10.161"
