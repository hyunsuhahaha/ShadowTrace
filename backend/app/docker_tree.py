"""Lists every container and image on an unauthenticated Docker Engine API
(the classic 2375/tcp misconfiguration), tagged like the other tree
commands.

The Docker API is plain HTTP + JSON, so this stays on stdlib
urllib.request rather than pulling in the docker-py client library for
what two GET requests cover.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request


def _get_json(base_url: str, path: str, timeout: float):
    with urllib.request.urlopen(f"{base_url}{path}", timeout=timeout) as response:
        return json.loads(response.read())


def build_tree_lines(containers: list[dict], images: list[dict]) -> list[str]:
    lines = ["D|containers"]
    for container in containers:
        names = container.get("Names") or [container.get("Id", "unknown")[:12]]
        name = names[0].lstrip("/")
        lines.append(f"F|containers/{name}")
    lines.append("D|images")
    for image in images:
        tags = image.get("RepoTags") or [image.get("Id", "unknown")[:19]]
        for tag in tags:
            lines.append(f"F|images/{tag}")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="List every container/image on an unauthenticated Docker API.")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)

    base_url = f"http://{args.host}:{args.port}"
    try:
        containers = _get_json(base_url, "/containers/json?all=true", args.timeout)
        images = _get_json(base_url, "/images/json", args.timeout)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        print(f"[-] Docker API 조회 실패: {exc}", file=sys.stderr)
        return 1

    for line in build_tree_lines(containers, images):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
