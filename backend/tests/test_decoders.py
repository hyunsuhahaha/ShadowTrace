import base64
from Cryptodome.Cipher import DES3
from Cryptodome.Util.Padding import pad
from app.modules.decoders.router import decrypt_roundcube_des, roundcube_des
from app.modules.decoders.schemas import RoundcubeDesIn

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
