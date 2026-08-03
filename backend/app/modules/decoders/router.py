from __future__ import annotations
import base64
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import APIRouter, File, HTTPException, UploadFile
from Cryptodome.Cipher import DES, DES3
from Cryptodome.Util.Padding import unpad
from .schemas import (
    DpapiCredentialIn, DpapiMasterkeyIn, PuttyKeyIn, RoundcubeDesIn, VncPasswordIn,
)

# VNC (RealVNC/TightVNC/UltraVNC) obfuscates the stored password with DES-ECB
# under a single fixed, publicly-documented key — 17:52:6b:06:23:4e:58:07 —
# except the RFB spec's DES implementation reverses the bit order within
# each key byte before use; these are that key's bytes pre-reversed.
VNC_DES_KEY = bytes([0xE8, 0x4A, 0xD6, 0x60, 0xC4, 0x72, 0x1A, 0xE0])

router = APIRouter(prefix="/api/decoders", tags=["Decoders"])
DPAPI_KEY_PATTERN = re.compile(r"Decrypted key:\s*0x([0-9a-fA-F]+)")
LSASS_DUMP_MAX_BYTES = 300 * 1024 * 1024


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


def decrypt_vnc_password(ciphertext_hex: str) -> str | None:
    try:
        raw = bytes.fromhex(ciphertext_hex.strip())
    except ValueError:
        return None
    if not raw or len(raw) % 8 != 0:
        return None
    try:
        plain = DES.new(VNC_DES_KEY, DES.MODE_ECB).decrypt(raw)
    except ValueError:
        return None
    try:
        text = plain.split(b"\x00", 1)[0].decode("ascii")
    except UnicodeDecodeError:
        return None
    return text[:8] or None


@router.post("/vnc-password")
def vnc_password(body: VncPasswordIn):
    return {"plaintext": decrypt_vnc_password(body.ciphertext_hex)}


def _run_tool(argv: list[str], name: str, timeout: int = 30) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise HTTPException(504, f"{name} timed out after {timeout} seconds")


def _run_dpapi(argv: list[str]) -> subprocess.CompletedProcess:
    return _run_tool(argv, "impacket-dpapi")


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


@router.post("/putty-to-openssh")
def putty_to_openssh(body: PuttyKeyIn):
    """A PuTTY .ppk private key (found in saved sessions, Pageant exports,
    etc.) isn't directly usable with ssh/impacket — puttygen converts it to
    OpenSSH format in one step, so this just wraps that rather than parsing
    the .ppk format (which has three incompatible versions) by hand."""
    binary = shutil.which("puttygen")
    if not binary:
        return {"installed": False, "private_key": None, "stderr": ""}
    with tempfile.TemporaryDirectory() as tmp:
        ppk_path = Path(tmp) / "key.ppk"
        ppk_path.write_text(body.ppk_content, encoding="utf-8")
        out_path = Path(tmp) / "key.openssh"
        completed = _run_tool(
            [binary, str(ppk_path), "-O", "private-openssh", "-o", str(out_path)],
            "puttygen", timeout=15)
        private_key = out_path.read_text(encoding="utf-8") if out_path.is_file() else None
    return {
        "installed": True, "private_key": private_key,
        "stderr": completed.stderr[:5_000], "exit_code": completed.returncode,
    }


@router.post("/pypykatz-lsass")
async def pypykatz_lsass(file: UploadFile = File(...)):
    """A dumped lsass.exe process (procdump, comsvcs.dll MiniDump, Task
    Manager, etc.) is a full Mimikatz-format minidump — pypykatz is a pure
    Python re-implementation of the same MSV/wdigest/Kerberos/DPAPI secret
    extraction, so this wraps it rather than reimplementing minidump
    parsing. Unlike the other decoders, the dump is uploaded as a file (it's
    binary and can run to hundreds of MB), not pasted as base64 text."""
    binary = shutil.which("pypykatz")
    if not binary:
        return {"installed": False, "raw_output": ""}
    content = await file.read(LSASS_DUMP_MAX_BYTES + 1)
    if len(content) > LSASS_DUMP_MAX_BYTES:
        raise HTTPException(413, f"Dump exceeds the {LSASS_DUMP_MAX_BYTES // (1024 * 1024)}MB limit")
    with tempfile.TemporaryDirectory() as tmp:
        dump_path = Path(tmp) / (file.filename or "lsass.dmp")
        dump_path.write_bytes(content)
        completed = _run_tool([binary, "lsa", "minidump", str(dump_path)],
                              "pypykatz", timeout=120)
    return {
        "installed": True, "raw_output": completed.stdout[:1_000_000],
        "stderr": completed.stderr[:20_000], "exit_code": completed.returncode,
    }
