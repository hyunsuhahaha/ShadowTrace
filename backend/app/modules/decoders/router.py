from __future__ import annotations
import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, HTTPException
from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import unpad
from .schemas import DpapiCredentialIn, DpapiMasterkeyIn, RoundcubeDesIn

router = APIRouter(prefix="/api/decoders", tags=["Decoders"])
DPAPI_KEY_PATTERN = re.compile(r"Decrypted key:\s*0x([0-9a-fA-F]+)")


def decrypt_roundcube_des(key: str, value: str) -> str | None:
    """Roundcube (pre-AES versions) encrypts the session table's stored IMAP
    password with DES-EDE3-CBC using config.inc.php's $config['des_key']
    verbatim as the 24-byte key (no KDF), with the IV as the first 8 bytes of
    the base64-decoded blob and the ciphertext as the rest. Padding is
    whatever the original PHP mcrypt call left — usually PKCS7, sometimes
    zero-padded — so PKCS7 is tried first and a NUL-strip is the fallback."""
    key_bytes = key.encode("utf-8")
    if len(key_bytes) != 24:
        return None
    try:
        raw = base64.b64decode(value, validate=False)
    except Exception:
        return None
    if len(raw) <= 8 or len(raw) % 8 != 0:
        return None
    iv, ciphertext = raw[:8], raw[8:]
    try:
        plain = DES3.new(key_bytes, DES3.MODE_CBC, iv).decrypt(ciphertext)
    except ValueError:
        return None
    try:
        return unpad(plain, 8).decode("utf-8")
    except ValueError:
        pass
    try:
        return plain.rstrip(b"\x00").decode("utf-8")
    except UnicodeDecodeError:
        return None


@router.post("/roundcube-des")
def roundcube_des(body: RoundcubeDesIn):
    return {"plaintext": decrypt_roundcube_des(body.key, body.value)}


def _run_dpapi(argv: list[str]) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, "impacket-dpapi timed out after 30 seconds")


@router.post("/dpapi-masterkey")
def dpapi_masterkey(body: DpapiMasterkeyIn):
    """Wraps impacket-dpapi rather than reimplementing MS-BKRP's masterkey
    derivation — this only handles the local user-password path (-sid
    -password), not the domain backup-key or SYSTEM/SECURITY hive paths."""
    binary = shutil.which("impacket-dpapi")
    if not binary:
        return {"installed": False, "decrypted_key": None, "raw_output": ""}
    try:
        raw = base64.b64decode(body.masterkey_b64, validate=False)
    except Exception:
        raise HTTPException(400, "masterkey_b64 is not valid base64")
    with tempfile.TemporaryDirectory() as tmp:
        mk_path = Path(tmp) / "masterkey"
        mk_path.write_bytes(raw)
        completed = _run_dpapi([binary, "masterkey", "-file", str(mk_path),
                                "-sid", body.sid, "-password", body.password])
    raw_output = completed.stdout[:100_000]
    match = DPAPI_KEY_PATTERN.search(raw_output)
    return {
        "installed": True, "decrypted_key": match.group(1) if match else None,
        "raw_output": raw_output, "stderr": completed.stderr[:20_000],
        "exit_code": completed.returncode,
    }


@router.post("/dpapi-credential")
def dpapi_credential(body: DpapiCredentialIn):
    binary = shutil.which("impacket-dpapi")
    if not binary:
        return {"installed": False, "raw_output": ""}
    try:
        raw = base64.b64decode(body.credential_b64, validate=False)
    except Exception:
        raise HTTPException(400, "credential_b64 is not valid base64")
    with tempfile.TemporaryDirectory() as tmp:
        cred_path = Path(tmp) / "credential"
        cred_path.write_bytes(raw)
        completed = _run_dpapi([binary, "credential", "-file", str(cred_path),
                                "-key", body.key_hex])
    return {
        "installed": True, "raw_output": completed.stdout[:100_000],
        "stderr": completed.stderr[:20_000], "exit_code": completed.returncode,
    }
