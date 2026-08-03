import base64
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import pad
from app.modules.decoders import router
from app.modules.decoders.router import decrypt_roundcube_des, roundcube_des
from app.modules.decoders.schemas import (
    DpapiCredentialIn, DpapiMasterkeyIn, RoundcubeDesIn,
)

KEY = "rcmail-!24ByteDESkey*Str"


def encrypt(plaintext: str, key: str = KEY, iv: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08") -> str:
    cipher = DES3.new(key.encode("utf-8"), DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode("utf-8"), 8))
    return base64.b64encode(iv + ciphertext).decode("ascii")


def test_decrypts_a_pkcs7_padded_roundcube_session_blob():
    blob = encrypt("595mO8DmwGeD")
    assert decrypt_roundcube_des(KEY, blob) == "595mO8DmwGeD"


def test_falls_back_to_stripping_zero_padding_when_pkcs7_is_invalid():
    # Older mcrypt-style callers zero-pad instead of PKCS7; craft a block
    # whose last byte can't be valid PKCS7 (0x00 is never a valid pad byte)
    # so the PKCS7 path fails and the NUL-strip fallback has to catch it.
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    padded = ("hunter2".encode("utf-8") + b"\x00" * (8 - len("hunter2") % 8))
    cipher = DES3.new(KEY.encode("utf-8"), DES3.MODE_CBC, iv)
    blob = base64.b64encode(iv + cipher.encrypt(padded)).decode("ascii")
    assert decrypt_roundcube_des(KEY, blob) == "hunter2"


def test_rejects_a_key_that_is_not_exactly_24_bytes():
    blob = encrypt("whatever")
    assert decrypt_roundcube_des("too-short", blob) is None
    assert decrypt_roundcube_des(KEY + "x", blob) is None


def test_rejects_malformed_input():
    assert decrypt_roundcube_des(KEY, "not-valid-base64!!!") is None
    assert decrypt_roundcube_des(KEY, base64.b64encode(b"short").decode()) is None


def test_endpoint_returns_plaintext_key():
    blob = encrypt("gY4Wr3a1evp4")
    result = roundcube_des(RoundcubeDesIn(key=KEY, value=blob))
    assert result == {"plaintext": "gY4Wr3a1evp4"}


def test_dpapi_masterkey_reports_not_installed_without_the_binary(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: None)
    result = router.dpapi_masterkey(DpapiMasterkeyIn(
        masterkey_b64=base64.b64encode(b"fake").decode(),
        sid="S-1-5-21-1-2-3-1000", password="hunter2"))
    assert result == {"installed": False, "decrypted_key": None, "raw_output": ""}


def test_dpapi_masterkey_rejects_invalid_base64(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/impacket-dpapi")
    with pytest.raises(HTTPException) as exc:
        router.dpapi_masterkey(DpapiMasterkeyIn(
            masterkey_b64="not valid base64!!!", sid="S-1-5-21-1-2-3-1000",
            password="hunter2"))
    assert exc.value.status_code == 400


def test_dpapi_masterkey_extracts_the_decrypted_key_from_stdout(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/impacket-dpapi")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(
            stdout="[MASTERKEYS]\nDecrypted key with User Key (SHA1)\n"
                   "Decrypted key: 0xdeadbeefcafebabe\n",
            stderr="", returncode=0)
    monkeypatch.setattr(router.subprocess, "run", fake_run)

    result = router.dpapi_masterkey(DpapiMasterkeyIn(
        masterkey_b64=base64.b64encode(b"fake-masterkey-bytes").decode(),
        sid="S-1-5-21-1-2-3-1000", password="hunter2"))
    assert result["installed"] is True
    assert result["decrypted_key"] == "deadbeefcafebabe"
    assert captured["argv"][:3] == ["/usr/bin/impacket-dpapi", "masterkey", "-file"]
    assert captured["argv"][-4:] == [
        "-sid", "S-1-5-21-1-2-3-1000", "-password", "hunter2"]


def test_dpapi_masterkey_times_out(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/impacket-dpapi")

    def timeout(*args, **kwargs):
        raise router.subprocess.TimeoutExpired(args[0], 30)
    monkeypatch.setattr(router.subprocess, "run", timeout)
    with pytest.raises(HTTPException) as exc:
        router.dpapi_masterkey(DpapiMasterkeyIn(
            masterkey_b64=base64.b64encode(b"fake").decode(),
            sid="S-1-5-21-1-2-3-1000", password="hunter2"))
    assert exc.value.status_code == 504


def test_dpapi_credential_reports_not_installed_without_the_binary(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: None)
    result = router.dpapi_credential(DpapiCredentialIn(
        credential_b64=base64.b64encode(b"fake").decode(), key_hex="deadbeef"))
    assert result == {"installed": False, "raw_output": ""}


def test_dpapi_credential_runs_with_the_supplied_key(monkeypatch):
    monkeypatch.setattr(router.shutil, "which", lambda _: "/usr/bin/impacket-dpapi")
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(
            stdout="[CREDENTIAL]\nusername: steph.cooper_adm\n"
                   "password: FivethChipOnItsWay2025!\n",
            stderr="", returncode=0)
    monkeypatch.setattr(router.subprocess, "run", fake_run)

    result = router.dpapi_credential(DpapiCredentialIn(
        credential_b64=base64.b64encode(b"fake-credential-bytes").decode(),
        key_hex="deadbeefcafebabe"))
    assert result["installed"] is True
    assert "steph.cooper_adm" in result["raw_output"]
    assert captured["argv"][:3] == ["/usr/bin/impacket-dpapi", "credential", "-file"]
    assert captured["argv"][-2:] == ["-key", "deadbeefcafebabe"]
