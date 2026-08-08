"""Walks the LDAP Directory Information Tree (DIT) -- literally what the
"directory" in "LDAP" refers to -- tagged like the other tree commands.

Every entry's DN already embeds its full ancestor path (cn=user1,ou=Users,
dc=corp,dc=local), so a single subtree search from the base DN is enough;
no per-level recursion needed, similar to IMAP's LIST "" "*". Every entry
is tagged F| for the same reason as IMAP's mailboxes: any entry could have
children, but there's no cheap way to know without a second query, and the
shared frontend tree builder already turns intermediate DN components into
expandable branches from the full path alone.
"""
from __future__ import annotations

import argparse
import sys

import ldap3


def discover_base_dn(connection: ldap3.Connection) -> str | None:
    connection.search("", "(objectClass=*)", search_scope=ldap3.BASE,
                       attributes=["namingContexts"])
    if not connection.entries:
        return None
    contexts = connection.entries[0]["namingContexts"].values
    return contexts[0] if contexts else None


def dn_to_path(dn: str, base_dn: str) -> str | None:
    """The base DN's own entry is always in the result set (it's the
    subtree search root) -- exclude it the same way PROPFIND's own
    walker excludes the requested collection itself."""
    if dn.lower() == base_dn.lower():
        return None
    components = [part.strip() for part in dn.split(",")]
    return "/".join(reversed(components))


def walk(connection: ldap3.Connection, base_dn: str) -> list[str]:
    connection.search(base_dn, "(objectClass=*)", search_scope=ldap3.SUBTREE, attributes=[])
    lines = []
    for entry in connection.entries:
        path = dn_to_path(str(entry.entry_dn), base_dn)
        if path:
            lines.append(f"F|{path}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Walk the LDAP DIT as a tree.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--username", default="")
    parser.add_argument("--password", default="")
    parser.add_argument("--base-dn", default="")
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    server = ldap3.Server(args.host, port=args.port, connect_timeout=args.timeout)
    try:
        connection = ldap3.Connection(
            server,
            user=args.username or None, password=args.password or None,
            authentication=ldap3.SIMPLE if args.username else ldap3.ANONYMOUS,
            receive_timeout=args.timeout,
        )
        if not connection.bind():
            print(f"[-] Bind 실패: {connection.result}", file=sys.stderr)
            return 1
    except ldap3.core.exceptions.LDAPException as exc:
        print(f"[-] 연결 실패: {exc}", file=sys.stderr)
        return 1

    base_dn = args.base_dn or discover_base_dn(connection)
    if not base_dn:
        print("[-] Base DN을 찾지 못했습니다 (--base-dn으로 직접 지정하세요)", file=sys.stderr)
        connection.unbind()
        return 1

    try:
        for line in walk(connection, base_dn):
            print(line)
    except ldap3.core.exceptions.LDAPException as exc:
        print(f"[-] 검색 실패: {exc}", file=sys.stderr)
        connection.unbind()
        return 1
    connection.unbind()
    return 0


if __name__ == "__main__":
    sys.exit(main())
