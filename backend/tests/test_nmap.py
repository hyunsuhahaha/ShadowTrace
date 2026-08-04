import os
import subprocess
from pathlib import Path
from app.nmap_parser import parse_nmap
from app.executor import (
    classify_execution_status,
    require_observation,
    update_execution_observations,
    update_service_identity,
)
from app.database import Base
from app.models import Execution, Project, Service, Target
from app.templates import catalog
from app.product_policy import public_policy
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

def test_parse_nmap():
    data=b'<nmaprun><host><address addr="10.10.10.10"/><ports><port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="3.0.3"/><script id="ftp-anon" output="disabled"/></port></ports></host></nmaprun>'
    host=parse_nmap(data)[0]
    assert host["ip"]=="10.10.10.10"
    assert host["services"][0]["product"]=="vsftpd"

def test_parse_nmap_merges_masscan_style_one_host_block_per_port():
    # masscan emits a separate <host> element per discovered port rather than
    # one <host> aggregating all ports the way Nmap does.
    data = (
        b'<nmaprun scanner="masscan">'
        b'<host><address addr="10.10.10.20" addrtype="ipv4"/><ports>'
        b'<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/></port>'
        b'</ports></host>'
        b'<host><address addr="10.10.10.20" addrtype="ipv4"/><ports>'
        b'<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/></port>'
        b'</ports></host>'
        b'</nmaprun>'
    )
    hosts = parse_nmap(data)
    assert len(hosts) == 1
    assert hosts[0]["ip"] == "10.10.10.20"
    assert {s["port"] for s in hosts[0]["services"]} == {22, 80}

def test_template_render_quotes_values():
    _, command, argv=catalog.render("ftp-anon",{"host":"10.10.10.10","port":"21"})
    assert argv[-1]=="10.10.10.10"
    assert "ftp-anon" in command

def test_every_service_exposes_an_explicit_product_version_probe():
    assert "service-version" in {
        item["id"] for item in catalog.commands_for("telnet", 23, "tcp")
    }
    assert "service-version-udp" in {
        item["id"] for item in catalog.commands_for("snmp", 161, "udp")
    }
    _, _, argv = catalog.render("service-version", {
        "host": "10.10.10.23",
        "port": "23",
        "output_dir": "/tmp/output",
    })
    assert "--version-all" in argv

def test_target_identity_probe_and_observation_persistence():
    _, _, hostname_argv = catalog.render("target-hostname-identity", {
        "host": "10.10.10.23",
        "output_dir": "/tmp/output",
    })
    assert "-R" in hostname_argv
    _, _, argv = catalog.render("target-os-identity", {
        "host": "10.10.10.23",
        "output_dir": "/tmp/output",
    })
    assert "-O" in argv
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        project = Project(name="lab")
        db.add(project); db.flush()
        target = Target(project_id=project.id, name="box", ip="10.10.10.23")
        db.add(target); db.flush()
        execution = Execution(
            target_id=target.id, template_id="target-os-identity",
            command="", cwd="/tmp",
        )
        db.add(execution); db.flush()
        xml = b"""<nmaprun><host><address addr="10.10.10.23"/>
          <hostnames><hostname name="box.lab"/></hostnames>
          <os><osmatch name="Linux 5.X"/></os></host></nmaprun>"""
        assert update_execution_observations(db, execution, xml)
        assert target.hostname == "box.lab"
        assert target.os_guess == "Linux 5.X"

def test_nmap_zero_hosts_is_not_reported_as_completed():
    assert classify_execution_status(
        0,
        ["nmap", "-Pn", "-sV", "10.10.10.23"],
        "Nmap done: 1 IP address (0 hosts up) scanned in 3.02 seconds\n",
        "",
    ) == "no_response"
    assert classify_execution_status(
        0, ["nmap", "-sV", "10.10.10.23"], "Host is up.\n", "",
    ) == "completed"
    assert require_observation(
        "completed",
        ["nmap", "-Pn", "-sV", "-oX", "/tmp/identity.xml", "10.10.10.23"],
        False,
    ) == "no_response"
    assert require_observation(
        "completed",
        ["nmap", "-Pn", "-sV", "-oX", "/tmp/identity.xml", "10.10.10.23"],
        True,
    ) == "completed"

def test_telnet_exposes_follow_up_version_investigation_commands():
    commands = {
        item["id"]: item for item in catalog.commands_for("telnet", 23, "tcp")
    }
    assert {"telnet-banner", "telnet-version-trace"} <= commands.keys()
    _, _, trace_argv = catalog.render("telnet-version-trace", {
        "host": "10.10.10.23",
        "port": "23",
        "output_dir": "/tmp/output",
    })
    assert "--version-trace" in trace_argv

def test_default_credential_audits_are_bounded():
    for service, port, template_id in [
        ("telnet", 23, "telnet-default-audit"),
        ("ssh", 22, "ssh-default-audit"),
    ]:
        assert template_id in {
            item["id"] for item in catalog.commands_for(service, port, "tcp")
        }
        item, command, _ = catalog.render(template_id, {
            "host": "10.10.10.23",
            "port": str(port),
        })
        assert item["risk"] == "high"
        assert "brute.start=2" in command
        assert "brute.threads=2" in command
        assert "brute.guesses=3" in command
        assert "unpwdb.userlimit=8" in command
        assert "unpwdb.passlimit=4" in command
        assert "unpwdb.timelimit=2m" in command

def test_ftp_uses_only_the_anonymous_protocol_dataset():
    commands = catalog.commands_for("ftp", 21, "tcp")
    ids = {item["id"] for item in commands}
    assert "ftp-anon" in ids
    assert "ftp-default-audit" not in ids
    ftp = next(item for item in commands if item["id"] == "ftp-anon")
    assert "anonymous 자격증명 대입" in ftp["name"]

def test_command_level_match_keeps_protocol_specific_audits_separate():
    mysql = {
        item["id"] for item in catalog.commands_for("mysql", 3306, "tcp")
    }
    postgres = {
        item["id"] for item in catalog.commands_for("postgresql", 5432, "tcp")
    }
    assert "mysql-credential-probe" in mysql
    assert "postgres-default-audit" not in mysql
    assert "postgres-default-audit" in postgres

def test_smb_commands_are_not_offered_for_ms_rpc_port():
    msrpc = {item["id"] for item in catalog.commands_for("msrpc", 135)}
    smb = {item["id"] for item in catalog.commands_for("microsoft-ds", 445)}
    assert "smb-enum" not in msrpc
    assert "smb-client" not in msrpc
    assert "msrpc-enum" in msrpc
    assert {"smb-enum", "smb-client"} <= smb
    assert "smb-security" in smb

def test_detected_service_name_beats_port_fallback():
    commands = {item["id"] for item in catalog.commands_for("ssh", 21)}
    assert "ssh-enum" in commands
    assert "ftp-anon" not in commands
    commands = {item["id"]: item for item in catalog.commands_for(
        "microsoft-ds", 445)}
    assert commands["smb-enum"]["command"].startswith("smbclient -N -L")
    assert commands["smb-null-session"]["command"].startswith("rpcclient -N")

def test_interactive_command_preview_renders_service_variables():
    item, command, argv = catalog.render(
        "smb-client", {"host": "10.0.0.4", "port": "445"},
        execution_mode="interactive",
    )
    assert item["id"] == "smb-client"
    assert command == "smbclient -L //10.0.0.4 -p 445"
    assert argv[-1] == "445"
    _, share_command, share_argv = catalog.render(
        "smb-share-client",
        {"host": "10.0.0.4", "port": "445", "share": "Work Shares"},
        execution_mode="interactive",
    )
    assert share_command == "smbclient //10.0.0.4/'Work Shares' -N -p 445"
    assert share_argv[1] == "//10.0.0.4/Work Shares"

def test_mysql_client_opens_with_the_discovered_username_and_always_prompts_for_a_password():
    # create_interactive_session() rejects a "password" variable outright
    # ("Passwords must be entered interactively"), so this always prompts
    # with a bare -p — even for a blank-password find, the user just hits
    # Enter — rather than trying to smuggle a known password into argv.
    item, command, argv = catalog.render(
        "mysql-client", {"host": "10.10.10.23", "port": "3306", "username": "root"},
        execution_mode="interactive",
    )
    assert item["id"] == "mysql-client"
    assert command == "mysql -h 10.10.10.23 -P 3306 -u root -p"
    assert argv[-1] == "-p"

def test_kerbrute_userenum_is_hidden_from_the_generic_list_but_renders_with_extra_variables():
    # domain/wordlist aren't nmap-derived, so — like http-directory-fuzz — this
    # command must stay out of commands_for()'s auto-populated list and only be
    # reachable through a direct catalog.render() call that supplies them.
    commands = {item["id"] for item in catalog.commands_for("kerberos-sec", 88)}
    assert "kerberos-user-enum-kerbrute" not in commands
    item, command, argv = catalog.render("kerberos-user-enum-kerbrute", {
        "host": "10.10.10.10", "domain": "corp.local",
        "wordlist": "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    })
    assert item["tool"] == "kerbrute"
    assert argv == [
        "kerbrute", "userenum", "-d", "corp.local", "--dc", "10.10.10.10",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ]
    assert command == (
        "kerbrute userenum -d corp.local --dc 10.10.10.10 "
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt")

def test_mssql_rid_brute_renders_with_manually_supplied_credentials():
    # Like the netexec credential-check entry it sits next to, this needs a
    # username/password the operator supplies, so it stays out of the
    # ms-sql-s auto-populated list and is only reachable via render().
    commands = {item["id"] for item in catalog.commands_for("ms-sql-s", 1433)}
    assert "mssql-rid-brute-netexec" not in commands
    item, command, argv = catalog.render("mssql-rid-brute-netexec", {
        "host": "10.10.10.18", "port": "1433", "username": "kevin", "password": "iNa2we6haRj2gaw!",
    })
    assert item["tool"] == "netexec"
    assert argv == [
        "nxc", "mssql", "10.10.10.18", "--port", "1433",
        "-u", "kevin", "-p", "iNa2we6haRj2gaw!", "--rid-brute",
    ]
    assert command == "nxc mssql 10.10.10.18 --port 1433 -u kevin -p 'iNa2we6haRj2gaw!' --rid-brute"

def test_ike_scan_commands_render_for_isakmp_service():
    commands = {item["id"] for item in catalog.commands_for("isakmp", 500, protocol="udp")}
    assert {"ike-scan-info", "ike-scan-aggressive-pskcrack"} <= commands
    item, command, argv = catalog.render("ike-scan-aggressive-pskcrack", {"host": "10.10.10.10"})
    assert item["tool"] == "ike-scan"
    assert argv == ["ike-scan", "-M", "-A", "--pskcrack=/dev/stdout", "10.10.10.10"]
    assert command == "ike-scan -M -A --pskcrack=/dev/stdout 10.10.10.10"

def test_tftp_get_file_is_hidden_from_the_generic_list_but_renders_with_a_path():
    # like http-directory-fuzz, the target filename isn't nmap-derived, so
    # this stays out of the auto-populated tftp list and needs render().
    commands = {item["id"] for item in catalog.commands_for("tftp", 69, protocol="udp")}
    assert "tftp-get-file" not in commands
    item, command, argv = catalog.render("tftp-get-file", {
        "host": "10.10.10.10", "path": "ciscortr.cfg"})
    assert item["tool"] == "curl"
    assert argv == ["curl", "-s", "tftp://10.10.10.10/ciscortr.cfg"]
    assert command == "curl -s tftp://10.10.10.10/ciscortr.cfg"

def test_constrained_delegation_getst_renders_with_manually_supplied_fields():
    commands = {item["id"] for item in catalog.commands_for("ldap", 389)}
    assert "ad-constrained-delegation-getst" not in commands
    item, command, argv = catalog.render("ad-constrained-delegation-getst", {
        "spn": "cifs/dc01.intelligence.htb", "target_username": "administrator",
        "host": "10.10.10.248", "domain": "intelligence.htb",
        "username": "svc_int$", "password": "aa07d7ff70386dfe0ae54c1de92b26e5",
    })
    assert item["tool"] == "impacket-getST"
    assert argv == [
        "impacket-getST", "-spn", "cifs/dc01.intelligence.htb", "-impersonate", "administrator",
        "-dc-ip", "10.10.10.248", "intelligence.htb/svc_int$:aa07d7ff70386dfe0ae54c1de92b26e5",
    ]

def test_silver_ticket_ticketer_renders_with_manually_supplied_fields():
    # like DCSync/BloodHound next to it, this needs fields the operator
    # gathers by hand (a cracked/dumped NTLM hash, the domain SID, an SPN,
    # target group RIDs) so it stays out of the auto-populated list.
    commands = {item["id"] for item in catalog.commands_for("ldap", 389)}
    assert "ad-silver-ticket-ticketer" not in commands
    item, command, argv = catalog.render("ad-silver-ticket-ticketer", {
        "nthash": "ef699384c3285c54128a3ee1ddb1a0cc",
        "domain_sid": "S-1-5-21-4088429403-1159899800-2753317549",
        "domain": "signed.htb", "spn": "MSSQLSvc/DC01.signed.htb:1433",
        "groups": "1105", "target_username": "Administrator",
    })
    assert item["tool"] == "impacket-ticketer"
    assert argv == [
        "impacket-ticketer", "-nthash", "ef699384c3285c54128a3ee1ddb1a0cc",
        "-domain-sid", "S-1-5-21-4088429403-1159899800-2753317549",
        "-domain", "signed.htb", "-spn", "MSSQLSvc/DC01.signed.htb:1433",
        "-groups", "1105", "Administrator",
    ]

def test_vhost_fuzz_is_hidden_from_the_generic_list_but_renders_with_a_wordlist():
    # like http-directory-fuzz, the wordlist isn't nmap-derived, so this
    # stays out of the auto-populated http list and needs render().
    commands = {item["id"] for item in catalog.commands_for("http", 80)}
    assert "http-vhost-fuzz" not in commands
    item, command, argv = catalog.render("http-vhost-fuzz", {
        "scheme": "http", "host": "10.10.11.80", "port": "80", "domain": "editor.htb",
        "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
    })
    assert item["tool"] == "ffuf"
    assert argv == [
        "ffuf", "-u", "http://10.10.11.80:80/", "-H", "Host: FUZZ.editor.htb",
        "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "-mc", "all", "-t", "40",
    ]
    assert command == (
        'ffuf -u http://10.10.11.80:80/ -H "Host: FUZZ.editor.htb" '
        "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc all -t 40")

def test_laps_password_netexec_renders_with_manually_supplied_credentials():
    commands = {item["id"] for item in catalog.commands_for("ldap", 389)}
    assert "ad-laps-password-netexec" not in commands
    item, command, argv = catalog.render("ad-laps-password-netexec", {
        "host": "10.10.11.x", "username": "t.hackett", "password": "Password123"})
    assert item["tool"] == "netexec"
    assert argv == ["nxc", "ldap", "10.10.11.x", "-u", "t.hackett", "-p", "Password123", "--laps"]

def test_gmsa_password_netexec_renders_with_manually_supplied_credentials():
    commands = {item["id"] for item in catalog.commands_for("ldap", 389)}
    assert "ad-gmsa-password-netexec" not in commands
    item, command, argv = catalog.render("ad-gmsa-password-netexec", {
        "host": "10.10.11.x", "username": "alfred", "password": "basketball"})
    assert item["tool"] == "netexec"
    assert argv == ["nxc", "ldap", "10.10.11.x", "-u", "alfred", "-p", "basketball", "--gmsa"]

def test_spring_actuator_commands_render_for_the_generic_http_list():
    commands = {item["id"] for item in catalog.commands_for("http", 80)}
    assert {"spring-actuator-check", "spring-actuator-env", "spring-actuator-sessions"} <= commands
    _, command, argv = catalog.render("spring-actuator-sessions", {
        "scheme": "http", "host": "10.10.11.10", "port": "8080"})
    assert argv == ["curl", "-s", "http://10.10.11.10:8080/actuator/sessions"]
    assert command == "curl -s http://10.10.11.10:8080/actuator/sessions"

def test_git_exposure_commands_render_for_the_generic_http_list():
    commands = {item["id"] for item in catalog.commands_for("http", 80)}
    assert {"git-head-check", "git-dumper-clone"} <= commands
    item, command, argv = catalog.render("git-head-check", {
        "scheme": "http", "host": "10.10.11.58", "port": "80"})
    assert item["tool"] == "curl"
    assert command == "curl -s http://10.10.11.58:80/.git/HEAD"
    item, command, argv = catalog.render("git-dumper-clone", {
        "scheme": "http", "host": "10.10.11.58", "port": "80",
        "output_dir": "/tmp/proj/outputs"})
    assert item["tool"] == "git-dumper"
    assert argv == [
        "git-dumper", "http://10.10.11.58:80/.git/", "/tmp/proj/outputs/git-dump"]

def test_current_auth_protocols_have_specific_reviewed_checks():
    expected = {
        ("smtp", 25, "tcp"): {"smtp-info", "smtp-default-audit"},
        ("http", 80, "tcp"): {"http-auth-finder", "http-default-audit"},
        ("microsoft-ds", 445, "tcp"): {
            "smb-null-session", "smb-default-audit",
        },
        ("ldap", 389, "tcp"): {"ldap-rootdse", "ldap-default-audit"},
        ("mysql", 3306, "tcp"): {
            "mysql-empty-password", "mysql-credential-probe",
        },
        ("ms-sql-s", 1433, "tcp"): {
            "mssql-empty-password", "mssql-default-audit",
        },
        ("redis", 6379, "tcp"): {
            "redis-unauthenticated-info", "redis-default-audit",
        },
        ("snmp", 161, "udp"): {"snmp-info", "snmp-community-audit"},
        ("ms-wbt-server", 3389, "tcp"): {
            "rdp-info", "rdp-default-audit",
        },
        ("imap", 143, "tcp"): {"imap-default-audit"},
        ("pop3", 110, "tcp"): {"pop3-default-audit"},
        ("vnc", 5900, "tcp"): {"vnc-info", "vnc-default-audit"},
        ("mongodb", 27017, "tcp"): {
            "mongodb-info", "mongodb-default-audit",
        },
        ("rsync", 873, "tcp"): {
            "rsync-modules", "rsync-default-audit",
        },
    }
    for (service, port, protocol), required in expected.items():
        actual = {
            item["id"] for item in catalog.commands_for(
                service, port, protocol)
        }
        assert required <= actual

def test_custom_audit_engines_only_claim_supported_limits():
    for template_id in [
        "smb-default-audit",
        "ldap-default-audit",
        "postgres-default-audit",
        "mssql-default-audit",
        "snmp-community-audit",
    ]:
        _, command, _ = catalog.render(template_id, {
            "host": "10.10.10.23",
            "port": "445",
        })
        assert "unpwdb.timelimit=2m" in command
        assert "brute.threads" not in command

def test_mysql_credential_probe_invokes_the_bundled_script_with_the_edited_candidates():
    # mysql-empty-password.nse hard-codes socket:set_timeout(5000) with no
    # script-arg to override it, so a slow handshake (e.g. a reverse-DNS
    # lookup on the client IP with skip-name-resolve unset) makes it miss a
    # real empty password. That script isn't ours to fix, so this direct
    # mysql-client probe needs its own generous timeout to survive the same
    # case — and takes the candidate list from the UI rather than a fixed
    # "root only" guess, same as every other audit in this catalog.
    _, command, argv = catalog.render("mysql-credential-probe", {
        "host": "10.10.10.23", "port": "3306", "repo_dir": "/opt/oscp-workspace",
        "username": "root,svc", "password": ",toor"})
    assert argv[:2] == ["bash", "/opt/oscp-workspace/backend/scripts/mysql_credential_probe.sh"]
    assert argv[2:] == ["10.10.10.23", "3306", "root,svc", ",toor"]

def test_mysql_credential_probe_script_tries_each_candidate_with_a_generous_timeout(tmp_path):
    script = Path(__file__).parents[1] / "scripts" / "mysql_credential_probe.sh"
    assert "timeout_seconds=30" in script.read_text()
    # Stub out the real `mysql` binary so this runs hermetically: only
    # "-u root" with no "-p" (the blank-password candidate) succeeds.
    fake_mysql = tmp_path / "mysql"
    fake_mysql.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ " $* " == *" -u root "* && " $* " != *" -p"* ]]; then\n'
        '  echo "CURRENT_USER()\\troot@%"; exit 0\n'
        "fi\n"
        'echo "ERROR 1045 (28000): Access denied" >&2; exit 1\n')
    fake_mysql.chmod(0o755)
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}"}

    result = subprocess.run(
        ["bash", str(script), "10.10.10.23", "3306", "svc,root", ",toor"],
        capture_output=True, text=True, env=env, timeout=10)
    assert result.returncode == 0
    assert "[-] FAILED svc:<empty>" in result.stdout
    assert "[-] FAILED svc:toor" in result.stdout
    assert "[+] SUCCESS root:<empty>" in result.stdout
    assert "root@%" in result.stdout

def test_mysql_credential_probe_script_rejects_too_many_combinations(tmp_path):
    script = Path(__file__).parents[1] / "scripts" / "mysql_credential_probe.sh"
    users = ",".join(f"u{i}" for i in range(7))
    passwords = ",".join(f"p{i}" for i in range(7))
    result = subprocess.run(
        ["bash", str(script), "10.10.10.23", "3306", users, passwords],
        capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert "상한 40개를 초과" in result.stdout


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


def test_successful_nmap_identity_output_updates_the_selected_service():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        project = Project(name="Lab", description="")
        db.add(project)
        db.flush()
        target = Target(project_id=project.id, name="Box", ip="10.10.10.23")
        db.add(target)
        db.flush()
        service = Service(
            target_id=target.id, port=23, protocol="tcp", state="open",
            name="telnet", product="", version="", extra_info="", scripts="{}",
            notes="", tags="[]",
        )
        db.add(service)
        db.flush()
        execution = Execution(
            target_id=target.id, service_id=service.id,
            template_id="telnet-info", command="nmap", cwd="/tmp",
            status="completed",
        )
        db.add(execution)
        db.flush()
        xml = b'<nmaprun><host><address addr="10.10.10.23"/><ports><port protocol="tcp" portid="23"><state state="open"/><service name="telnet" product="Linux telnetd" version="0.17"/></port></ports></host></nmaprun>'

        assert update_service_identity(db, execution, xml) is True
        assert (service.product, service.version) == ("Linux telnetd", "0.17")
