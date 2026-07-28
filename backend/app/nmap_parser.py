from defusedxml import ElementTree as ET

def parse_nmap(content: bytes):
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("XML file is too large")
    root = ET.fromstring(content)
    hosts = []
    for host in root.findall("host"):
        address = host.find("address")
        hostname = host.find("./hostnames/hostname")
        osmatch = host.find("./os/osmatch")
        services = []
        for port in host.findall("./ports/port"):
            state = port.find("state")
            svc = port.find("service")
            scripts = [{"id": s.get("id",""), "output": s.get("output","")} for s in port.findall("script")]
            services.append({
                "port": int(port.get("portid","0")), "protocol": port.get("protocol","tcp"),
                "state": state.get("state","unknown") if state is not None else "unknown",
                "name": svc.get("name","unknown") if svc is not None else "unknown",
                "product": svc.get("product","") if svc is not None else "",
                "version": svc.get("version","") if svc is not None else "",
                "extra_info": svc.get("extrainfo","") if svc is not None else "",
                "scripts": scripts,
            })
        hosts.append({"ip": address.get("addr","") if address is not None else "",
                      "hostname": hostname.get("name","") if hostname is not None else "",
                      "os_guess": osmatch.get("name","") if osmatch is not None else "",
                      "services": services})
    return hosts
