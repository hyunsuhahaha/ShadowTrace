#!/usr/bin/env bash
# Walks the whole MIB tree in one request. Unlike the other tree commands
# this isn't really a filesystem-shaped hierarchy -- it's config/telemetry
# values, not files -- so this only surfaces structure, not each value;
# run the existing snmp-info command for actual values once you've found
# something worth looking at closer.
#
# When MIB names are loaded, snmpwalk prints "MODULE::name.index = ...",
# which groups naturally into <module>/<name>.<index>. When they aren't
# (verified live: happens even on this Kali install depending on which
# MIBs are downloaded), it falls back to a bare "iso.3.6.1..." OID with no
# module prefix -- that's split on "." into the same path shape so at
# least shared branches (most entries share a long common OID prefix)
# still group together instead of dumping thousands of flat top-level
# leaves (verified live: an unfiltered walk here returned 23000+ lines).
set -uo pipefail

host="$1"
port="$2"
community="${3:-public}"
timeout_seconds=15
max_entries=2000

timeout "$timeout_seconds" snmpwalk -v2c -c "$community" "${host}:${port}" 2>/dev/null | awk '
  match($0, /^([A-Za-z][A-Za-z0-9_-]*)::([^ ]+) = /, m) {
    print "F|" m[1] "/" m[2]
    next
  }
  match($0, /^\.?([A-Za-z0-9.]+) = /, m) {
    gsub(/\./, "/", m[1])
    sub(/^\//, "", m[1])
    print "F|" m[1]
  }
' | head -n "$max_entries"
