#!/usr/bin/env bash
# Tries a small, fixed set of MySQL username/password candidates with the
# real mysql client instead of nmap's Lua reimplementation of the protocol.
# nmap's mysql-empty-password/mysql-brute scripts can miss a real hit when
# the server's handshake is slow (e.g. a reverse-DNS lookup on the client
# IP with skip-name-resolve unset) — every attempt here uses the same
# generous timeout for exactly that reason. root with a blank password is
# tried first since it's by far the most common real finding.
set -uo pipefail

host="$1"
port="$2"
timeout_seconds=30
users=(root mysql admin)
passwords=("" root mysql password)
attempted=0

for user in "${users[@]}"; do
  for password in "${passwords[@]}"; do
    attempted=$((attempted + 1))
    label="$user:${password:-<empty>}"
    if [ -z "$password" ]; then
      output=$(timeout "$timeout_seconds" mysql -h "$host" -P "$port" -u "$user" \
        --connect-timeout="$timeout_seconds" -e "SELECT CURRENT_USER(), VERSION();" 2>&1)
    else
      output=$(timeout "$timeout_seconds" mysql -h "$host" -P "$port" -u "$user" -p"$password" \
        --connect-timeout="$timeout_seconds" -e "SELECT CURRENT_USER(), VERSION();" 2>&1)
    fi
    if [ $? -eq 0 ]; then
      echo "[+] SUCCESS $label"
      echo "$output"
      exit 0
    fi
    echo "[-] FAILED $label"
  done
done
echo "[-] No valid MySQL credentials found among $attempted candidates."
exit 1
