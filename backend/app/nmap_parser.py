from defusedxml import ElementTree as ET

def parse_nmap(content: bytes):
    """Parse Nmap-schema XML, including masscan's output (which emits one
    <host> block per discovered port rather than one per address)."""
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("XML file is too large")
    root = ET.fromstring(content)
    hosts: dict[str, dict] = {}
    order: list[str] = []
    for host in root.findall("host"):
        address = host.find("address")
        ip = address.get("addr", "") if address is not None else ""
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "hostname": "", "os_guess": "", "services": []}
            order.append(ip)
        entry = hosts[ip]
        hostname = host.find("./hostnames/hostname")
        osmatch = host.find("./os/osmatch")
        if hostname is not None and hostname.get("name"):
            entry["hostname"] = hostname.get("name")
        if osmatch is not None and osmatch.get("name"):
            entry["os_guess"] = osmatch.get("name")
        services = entry["services"]
        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            scripts = [{"id": s.get("id",""), "output": s.get("output","")} for s in port.findall("script")]
            cpe = [node.text.strip() for node in port.findall("./service/cpe")
                   if node.text and node.text.strip()]
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            name = svc.get("name", "unknown") if svc is not None else "unknown"
            tls = tunnel.lower() in {"ssl", "tls"} or name.lower().startswith("ssl/")
            services.append({
                "port": int(port.get("portid","0")), "protocol": port.get("protocol","tcp"),
                "state": state.get("state","unknown") if state is not None else "unknown",
                "name": name,
                "product": svc.get("product","") if svc is not None else "",
                "version": svc.get("version","") if svc is not None else "",
                "extra_info": svc.get("extrainfo","") if svc is not None else "",
                "scripts": scripts,
                "cpe": cpe,
                "tls": tls,
                "detection_evidence": {
                    "method": svc.get("method", "") if svc is not None else "",
                    "confidence": int(svc.get("conf", "0") or 0) if svc is not None else 0,
                    "tunnel": tunnel,
                    "service_name": name,
                    "script_ids": [item["id"] for item in scripts if item["id"]],
                },
            })
    return [hosts[ip] for ip in order]
