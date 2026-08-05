import base64
import re
from pathlib import Path

# hashcat -m mode numbers, restricted to hash families that appear
# unambiguously in OSCP-style loot (secretsdump, kerberoasting, ASREP
# roasting, cracked Linux shadow entries, archives, WPA handshakes).
# Verified against https://hashcat.net/wiki/doku.php?id=example_hashes.
#
# "detect" is a JS-and-Python-compatible regex checked (in list order)
# against the first non-empty line the user pastes, so the UI can
# pre-select a mode instead of making the user look up -m by hand. It is
# a best-effort suggestion, not authoritative — the dropdown stays
# manually overridable because e.g. a bare 32-hex string is genuinely
# ambiguous between MD5 and a loose NTLM hash.
HASH_MODES = [
    {"id": "ntlm", "name": "NTLM (SAM/NTDS, secretsdump)", "mode": "1000",
     "example": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c",
     "detect": r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$"},
    {"id": "netntlmv2", "name": "NetNTLMv2", "mode": "5600",
     "example": "admin::CORP:1122334455667788:aaaa...:0101...",
     "detect": r"^[^:\s]+::[^:\s]*:[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9a-fA-F]+$"},
    {"id": "kerberoast", "name": "Kerberoasting (TGS-REP, etype 23)", "mode": "13100",
     "example": "$krb5tgs$23$*user$REALM$spn*$...",
     "detect": r"^\$krb5tgs\$23\$"},
    {"id": "asreproast", "name": "AS-REP Roasting (etype 23)", "mode": "18200",
     "example": "$krb5asrep$23$user@REALM:...",
     "detect": r"^\$krb5asrep\$23\$"},
    {"id": "linux_sha512crypt", "name": "Linux shadow · sha512crypt ($6$)", "mode": "1800",
     "example": "$6$saltsalt$hash...", "detect": r"^\$6\$"},
    {"id": "linux_md5crypt", "name": "Linux shadow · md5crypt ($1$)", "mode": "500",
     "example": "$1$saltsalt$hash...", "detect": r"^\$1\$"},
    {"id": "bcrypt", "name": "bcrypt (Linux/Unix, 최신 웹서비스)", "mode": "3200",
     "example": "$2y$05$saltsaltsaltsaltsaltsu.hash...", "detect": r"^\$2[abxy]\$"},
    {"id": "winzip", "name": "WinZip (AES)", "mode": "13600",
     "example": "$zip2$*0*...", "detect": r"^\$zip2\$"},
    # Legacy ZipCrypto (`zip -e`) is what most OSCP loot zips actually use,
    # unlike WinZip AES above. hashcat's PKZIP family splits into five
    # submodes by compression/entry-count that a $pkzip$ hash string alone
    # doesn't unambiguously reveal, so only the most common submode
    # (compressed entries) auto-detects; the rest are manual-only picks in
    # the dropdown, same spirit as the "detect is best-effort" note above.
    {"id": "pkzip", "name": "PKZIP/ZipCrypto (구형, 압축됨)", "mode": "17200",
     "example": "$pkzip$1*1*2*0*...*$/pkzip$", "detect": r"^\$pkzip\$"},
    {"id": "pkzip_uncompressed", "name": "PKZIP/ZipCrypto (구형, 비압축·stored)", "mode": "17210",
     "example": "$pkzip$1*1*2*0*...*$/pkzip$", "detect": r"(?!)"},
    {"id": "pkzip_multi_compressed", "name": "PKZIP/ZipCrypto (다중 파일, 압축됨)", "mode": "17220",
     "example": "$pkzip$8*2*...*$/pkzip$", "detect": r"(?!)"},
    {"id": "pkzip_multi_mixed", "name": "PKZIP/ZipCrypto (다중 파일, 혼합)", "mode": "17225",
     "example": "$pkzip$8*2*...*$/pkzip$", "detect": r"(?!)"},
    {"id": "pkzip_multi_checksum", "name": "PKZIP/ZipCrypto (다중 파일, 체크섬만)", "mode": "17230",
     "example": "$pkzip$8*2*...*$/pkzip$", "detect": r"(?!)"},
    {"id": "sevenzip", "name": "7-Zip", "mode": "11600",
     "example": "$7z$2$19$0$salt$8$iv$...", "detect": r"^\$7z\$"},
    {"id": "rar5", "name": "RAR5", "mode": "13000",
     "example": "$rar5$16$salt$15$iv$8$checksum", "detect": r"^\$rar5\$"},
    {"id": "keepass", "name": "KeePass 1/2 (keepass2john)", "mode": "13400",
     "example": "$keepass$*2*60000*0*...", "detect": r"^\$keepass\$\*"},
    {"id": "sha256_salt_pass", "name": "salted SHA256 (sha256($salt.$pass), 웹앱 DB)",
     "mode": "1420", "example": "hash(64자 hex):salt",
     # hash:salt is the only unambiguous shape available for this mode — a
     # bare 64-hex string is already claimed by plain sha256 above.
     "detect": r"^[0-9a-fA-F]{64}:"},
    # office2john.py (from the john project) writes the version into the hash
    # itself ($office$*2007*..., *2010*, *2013*), so each version gets its
    # own hashcat -m number and its own detect regex on that field.
    {"id": "ms_office_2007", "name": "MS Office 2007", "mode": "9400",
     "example": "$office$*2007*20*128*16*salt*hash*verifier",
     "detect": r"^\$office\$\*2007\*"},
    {"id": "ms_office_2010", "name": "MS Office 2010", "mode": "9500",
     "example": "$office$*2010*100000*128*16*salt*hash*verifier",
     "detect": r"^\$office\$\*2010\*"},
    {"id": "ms_office_2013", "name": "MS Office 2013+", "mode": "9600",
     "example": "$office$*2013*100000*256*16*salt*hash*verifier",
     "detect": r"^\$office\$\*2013\*"},
    {"id": "wpa", "name": "WPA-PBKDF2 (PMKID/EAPOL)", "mode": "22000",
     # No inline (?i) here: this pattern is reused verbatim as a JS RegExp
     # on the frontend for hash-mode auto-detection, and JS doesn't support
     # Python's inline flag groups. hcxpcapngtool always emits "WPA" upper-case.
     "detect": r"^WPA\*0[12]\*",
     "example": "WPA*02*hash*mac_ap*mac_sta*essid***"},
    {"id": "werkzeug_pbkdf2", "name": "Werkzeug/Flask PBKDF2-SHA256", "mode": "10900",
     "example": "pbkdf2:sha256:600000$saltsalt$" + "a" * 64,
     "detect": r"^pbkdf2:sha256:\d+\$"},
    {"id": "pbkdf2_sha256_generic", "name": "PBKDF2-HMAC-SHA256 (일반, 예: Gitea)", "mode": "10900",
     # Already hashcat -m 10900's own native input line — no transform. This
     # is what a Gitea `passwd`/`salt` hex column pair looks like once
     # base64-re-encoded (see the Gitea hash formatter), distinct from
     # Werkzeug's own on-disk string format above.
     "example": "sha256:50000:c2FsdHNhbHQ=:" + "aGFzaGhhc2g=",
     "detect": r"^sha256:\d+:"},
    {"id": "ike_psk", "name": "IKE-PSK (Aggressive Mode, SHA1)", "mode": "5400",
     # ike-scan's own --pskcrack=/dev/stdout output is already hashcat -m
     # 5400's native input line (colon-separated hex fields) — no reformatting
     # needed, unlike the Werkzeug PBKDF2 mode above.
     "example": "<init_cookie>:<resp_cookie>:<sa>:<nonce_i>:<nonce_r>:<ke_i>:<ke_r>:<hash_r>:1",
     "detect": r"^[0-9a-fA-F]+(?::[0-9a-fA-F]+){6,}$"},
    {"id": "sha256", "name": "SHA256 (일반 체크섬)", "mode": "1400",
     "example": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
     "detect": r"^[0-9a-fA-F]{64}$"},
    {"id": "md5", "name": "MD5 (구형 웹사이트, 단순 체크섬)", "mode": "0",
     "example": "5f4dcc3b5aa765d61d8327deb882cf99",
     "detect": r"^[0-9a-fA-F]{32}$"},
]
HASH_MODE_INDEX = {item["id"]: item for item in HASH_MODES}


def detect_hash_mode(sample: str) -> str | None:
    """Best-effort id lookup for a single pasted hash line, in HASH_MODES
    order. Returns None rather than guessing when nothing matches."""
    text = sample.strip()
    if not text:
        return None
    for item in HASH_MODES:
        if re.match(item["detect"], text):
            return item["id"]
    return None


_WERKZEUG_PBKDF2 = re.compile(r"^pbkdf2:sha256:(\d+)\$([^$]+)\$([0-9a-fA-F]+)$")


def _werkzeug_to_hashcat_10900(line: str) -> str:
    """Werkzeug's own storage format (`pbkdf2:sha256:<iter>$<salt>$<hexhash>`,
    salt as raw ASCII, digest as hex) isn't hashcat -m 10900's input format
    (`sha256:<iter>:<b64 salt>:<b64 hash>`) — hashcat would just reject the
    line as-is, so every hash of this mode is re-encoded before being
    written to hashes.txt."""
    match = _WERKZEUG_PBKDF2.match(line.strip())
    if not match:
        return line
    iterations, salt, hexhash = match.groups()
    salt_b64 = base64.b64encode(salt.encode()).decode()
    hash_b64 = base64.b64encode(bytes.fromhex(hexhash)).decode()
    return f"sha256:{iterations}:{salt_b64}:{hash_b64}"


# Per-mode re-encoders for hash formats whose natural/pasted form isn't
# already what hashcat expects on the command line (most modes need none —
# NTLM, kerberoast, etc. are pasted in hashcat's own native format).
HASH_LINE_TRANSFORMS = {
    "werkzeug_pbkdf2": _werkzeug_to_hashcat_10900,
}


def to_hashcat_line(hash_mode_id: str, line: str) -> str:
    transform = HASH_LINE_TRANSFORMS.get(hash_mode_id)
    return transform(line) if transform else line

CANDIDATE_WORDLISTS = [
    {"id": "rockyou", "name": "rockyou.txt", "path": "/usr/share/wordlists/rockyou.txt",
     "gzip_hint": "/usr/share/wordlists/rockyou.txt.gz"},
    {"id": "fasttrack", "name": "fasttrack.txt",
     "path": "/usr/share/wordlists/fasttrack.txt"},
    {"id": "dirb_common", "name": "dirb common.txt (small, quick pass)",
     "path": "/usr/share/wordlists/dirb/common.txt"},
]
CANDIDATE_RULES = [
    {"id": "best64", "name": "best64.rule", "path": "/usr/share/hashcat/rules/best64.rule"},
]


def wordlists() -> list[dict]:
    result = []
    for item in CANDIDATE_WORDLISTS:
        path = Path(item["path"])
        entry = {"id": item["id"], "name": item["name"], "path": item["path"],
                  "installed": path.is_file()}
        gzip_hint = item.get("gzip_hint")
        if not entry["installed"] and gzip_hint and Path(gzip_hint).is_file():
            entry["hint"] = f"gunzip {gzip_hint}"
        result.append(entry)
    return result


def rules() -> list[dict]:
    return [{"id": item["id"], "name": item["name"], "path": item["path"],
             "installed": Path(item["path"]).is_file()} for item in CANDIDATE_RULES]


def wordlist_path(wordlist_id: str) -> str | None:
    for item in CANDIDATE_WORDLISTS:
        if item["id"] == wordlist_id and Path(item["path"]).is_file():
            return item["path"]
    return None


def rule_path(rule_id: str) -> str | None:
    for item in CANDIDATE_RULES:
        if item["id"] == rule_id and Path(item["path"]).is_file():
            return item["path"]
    return None
