from app.nmap_parser import parse_nmap
from app.templates import catalog
from app.product_policy import public_policy

def test_parse_nmap():
    data=b'<nmaprun><host><address addr="10.10.10.10"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.3"/><script id="ftp-anon" output="disabled"/></port></ports></host></nmaprun>'
    host=parse_nmap(data)[0]
    assert host["ip"]=="10.10.10.10"
    assert host["services"][0]["product"]=="vsftpd"

def test_template_render_quotes_values():
    _, command, argv=catalog.render("ftp-anon",{"host":"10.10.10.10","port":"21"})
    assert argv[-1]=="10.10.10.10"
    assert "ftp-anon" in command

def test_xxe_rejected():
    bad=b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><nmaprun>&e;</nmaprun>'
    try: parse_nmap(bad)
    except Exception: return
    raise AssertionError("XXE was not rejected")

def test_product_policy_keeps_automatic_attack_out_of_scope():
    policy = public_policy()
    assert policy["priority"][0] == "scan_center"
    assert "automatic_exploit_selection_or_execution" in policy["prohibited"]
    assert "user_selected_enumeration_execution" in policy["allowed"]
