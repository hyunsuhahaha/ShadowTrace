from pathlib import Path
import re, shlex, yaml

ALLOWED = {"host","port","protocol","scheme","username","password","domain","wordlist",
           "output_dir","project_dir","target_dir","lhost","lport"}
TOKEN = re.compile(r"\{([a-z_]+)\}")

class Catalog:
    def __init__(self):
        self.path = Path(__file__).parents[1] / "templates"
        self.items = {}
        self.reload()
    def reload(self):
        self.items = {}
        for path in self.path.glob("*.yaml"):
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            for key, value in data.items():
                value["key"] = key
                for command in value.get("commands", []):
                    command["service_key"] = key
                    self.items[command["id"]] = command
    def commands_for(self, service: str, port: int):
        result = []
        for command in self.items.values():
            group = command["service_key"]
            data = next((yaml.safe_load(p.read_text(encoding="utf-8")).get(group)
                         for p in self.path.glob("*.yaml")
                         if group in (yaml.safe_load(p.read_text(encoding="utf-8")) or {})), None)
            if data and (service.lower() in data["match"].get("services", []) or port in data["match"].get("ports", [])):
                result.append(command)
        return result
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
