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
    assert "mysql-default-audit" in mysql
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

def test_current_auth_protocols_have_specific_reviewed_checks():
    expected = {
        ("smtp", 25, "tcp"): {"smtp-info", "smtp-default-audit"},
        ("http", 80, "tcp"): {"http-auth-finder", "http-default-audit"},
        ("microsoft-ds", 445, "tcp"): {
            "smb-null-session", "smb-default-audit",
        },
        ("ldap", 389, "tcp"): {"ldap-rootdse", "ldap-default-audit"},
        ("mysql", 3306, "tcp"): {
            "mysql-empty-password", "mysql-default-audit",
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
