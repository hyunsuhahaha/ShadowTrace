from pathlib import Path
import re, shlex, yaml

ALLOWED = {"host","port","protocol","scheme","username","password","domain","wordlist",
           "output_dir","project_dir","target_dir","repo_dir","lhost","lport","share","path",
           "nthash","domain_sid","spn","groups","target_username","keyword","extensions",
           "interface","traversal_url","match_pattern"}
# host/port/scheme/protocol come from the selected target+service; the
# *_dir tokens come from the project layout. Everything else in ALLOWED is
# something only the person running the command can supply.
SYSTEM_PROVIDED = {"host", "port", "protocol", "scheme",
                    "output_dir", "project_dir", "target_dir", "repo_dir"}
TOKEN = re.compile(r"\{([a-z_]+)\}")

class Catalog:
    def __init__(self):
        self.path = Path(__file__).parents[1] / "templates"
        self.items = {}
        self.reload()
    def reload(self):
        self.items = {}
        self.groups = {}
        for path in (self.path / "services.yaml",):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for key, value in data.items():
                self.groups[key] = value
                value["key"] = key
                for command in value.get("commands", []):
                    command["service_key"] = key
                    self.items[command["id"]] = command
    def commands_for(self, service: str, port: int, protocol: str = "tcp",
                     product: str = "", cpe: list[str] | None = None,
                     tls: bool = False):
        result = []
        normalized = service.lower().strip()
        unknown = normalized in {"", "unknown", "tcpwrapped"}
        for command in self.items.values():
            group = command["service_key"]
            data = self.groups.get(group)
            match = command.get("match") or (data or {}).get("match", {})
            service_match = normalized in match.get("services", [])
            # A port is only fallback evidence when Nmap did not identify the
            # protocol. This prevents, for example, SSH on 21 from receiving
            # FTP commands while still helping genuinely unknown services.
            port_fallback = unknown and port in match.get("ports", [])
            if service_match or port_fallback:
                result.append(command)
        identity_id = "service-version-udp" if protocol.lower() == "udp" else "service-version"
        identity = self.items.get(identity_id)
        if identity and all(item["id"] != identity_id for item in result):
            result.insert(0, identity)
        return result
    def list_all(self):
        """Every command grouped by category, independent of what a target's
        Nmap results matched — for browsing/running a tool the auto-matcher
        missed (an unusual port, a misclassified service)."""
        groups = []
        for key, group in self.groups.items():
            commands = []
            for command in group.get("commands", []):
                needed = set(TOKEN.findall(command["command"]))
                commands.append({
                    "id": command["id"], "name": command["name"],
                    "description": command["description"], "risk": command["risk"],
                    "tool": command["tool"], "execution_mode": command["execution_mode"],
                    "command": command["command"],
                    "needs_service": bool(needed & {"port", "scheme", "protocol"}),
                    "variables": sorted(needed & (ALLOWED - SYSTEM_PROVIDED)),
                })
            if commands:
                groups.append({
                    "key": key, "display_name": group.get("display_name", key),
                    "commands": commands,
                })
        return groups

    def render(self, template_id: str, variables: dict[str, str],
               execution_mode: str = "captured"):
        item = self.items.get(template_id)
        if not item or item.get("execution_mode") != execution_mode:
            raise ValueError("Unknown or unsupported template")
        needed = set(TOKEN.findall(item["command"]))
        if not needed <= ALLOWED or not needed <= variables.keys():
            raise ValueError("Missing or invalid template variables")
        safe = {k: shlex.quote(str(v)) for k, v in variables.items() if k in ALLOWED}
        command = item["command"].format_map(safe)
        return item, command, shlex.split(command)

catalog = Catalog()
