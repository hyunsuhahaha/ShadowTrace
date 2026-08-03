from __future__ import annotations
import base64
from fastapi import APIRouter
from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import unpad
from .schemas import RoundcubeDesIn

router = APIRouter(prefix="/api/decoders", tags=["Decoders"])


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
