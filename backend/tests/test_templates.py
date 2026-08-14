import shlex
from app.modules.core.router import tool_catalog
from app.templates import catalog


def test_list_all_groups_every_command_and_flags_the_variables_a_user_must_supply():
    groups = catalog.list_all()
    total = sum(len(group["commands"]) for group in groups)
    assert total == len(catalog.items)

    http = next(group for group in groups if group["key"] == "http")
    by_id = {command["id"]: command for command in http["commands"]}
    assert by_id["http-param-fuzz"]["variables"] == ["path", "wordlist"]
    assert by_id["http-param-fuzz"]["needs_service"] is True
    assert by_id["http-headers"]["variables"] == []
    assert by_id["http-headers"]["needs_service"] is True


def test_list_all_omits_system_provided_tokens_from_the_user_input_list():
    groups = catalog.list_all()
    smb = next(group for group in groups if group["key"] == "smb")
    enum = next(c for c in smb["commands"] if c["id"] == "smb-enum")
    assert "host" not in enum["variables"]
    assert "port" not in enum["variables"]
    assert enum["needs_service"] is True


def test_list_all_flags_responder_as_needing_only_an_interface_not_a_service():
    groups = catalog.list_all()
    listeners = next(group for group in groups if group["key"] == "listeners")
    responder = next(c for c in listeners["commands"] if c["id"] == "responder-listener")
    assert responder["variables"] == ["interface"]
    assert responder["needs_service"] is False
    assert responder["execution_mode"] == "interactive"


def test_list_all_skips_groups_with_no_commands():
    groups = catalog.list_all()
    assert all(group["commands"] for group in groups)


def test_tool_catalog_endpoint_wraps_list_all_under_a_groups_key():
    body = tool_catalog()
    assert body["groups"] == catalog.list_all()


def test_docker_api_tree_renders_without_credentials():
    item, command, argv = catalog.render("docker-api-tree", {
        "host": "10.10.10.10", "port": "2375", "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.docker_tree",
        "--host", "10.10.10.10", "--port", "2375",
    ]


def test_docker_api_detect_always_uses_plain_http():
    # 2376/tcp requires a client cert (TLS), so it's never the
    # unauthenticated-misconfig case this check is for.
    item, command, argv = catalog.render("docker-api-detect", {
        "host": "10.10.10.10", "port": "2375",
    })
    assert argv == ["curl", "-s", "http://10.10.10.10:2375/version"]


def test_mongodb_db_tree_renders_without_credentials():
    item, command, argv = catalog.render("mongodb-db-tree", {
        "host": "10.10.10.10", "port": "27017", "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.mongodb_tree",
        "--host", "10.10.10.10", "--port", "27017",
    ]


def test_snmp_oid_tree_renders_with_the_community_string():
    item, command, argv = catalog.render("snmp-oid-tree", {
        "host": "10.10.10.10", "port": "161", "password": "public",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/snmp_tree.sh",
        "10.10.10.10", "161", "public",
    ]


def test_postgres_db_tree_renders_with_credentials():
    item, command, argv = catalog.render("postgres-db-tree", {
        "host": "10.10.10.10", "port": "5432", "username": "postgres", "password": "",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/postgres_db_tree.sh",
        "10.10.10.10", "5432", "postgres", "",
    ]


def test_mssql_db_tree_renders_with_credentials_and_domain():
    item, command, argv = catalog.render("mssql-db-tree", {
        "host": "10.10.10.10", "port": "1433", "username": "sa", "password": "secret",
        "domain": "", "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/mssql_db_tree.sh",
        "10.10.10.10", "1433", "sa", "secret", "",
    ]


def test_ldap_dit_tree_renders_with_optional_credentials():
    item, command, argv = catalog.render("ldap-dit-tree", {
        "host": "10.10.10.10", "port": "389", "username": "", "password": "",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.ldap_tree",
        "--host", "10.10.10.10", "--port", "389", "--username", "", "--password", "",
    ]


def test_svn_dump_recover_renders_with_the_repo_scoped_output_dir():
    item, command, argv = catalog.render("svn-dump-recover", {
        "host": "10.10.10.10", "port": "80", "scheme": "http",
        "output_dir": "/tmp/out", "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.svn_dump",
        "--url", "http://10.10.10.10:80", "--output-dir", "/tmp/out/svn-dump",
    ]


def test_mysql_db_tree_renders_with_credentials():
    item, command, argv = catalog.render("mysql-db-tree", {
        "host": "10.10.10.10", "port": "3306", "username": "root", "password": "",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/mysql_db_tree.sh",
        "10.10.10.10", "3306", "root", "",
    ]


def test_redis_key_tree_renders_with_an_optional_password():
    item, command, argv = catalog.render("redis-key-tree", {
        "host": "10.10.10.10", "port": "6379", "password": "",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/redis_tree.sh",
        "10.10.10.10", "6379", "",
    ]


def test_imap_mailbox_tree_renders_with_credentials():
    item, command, argv = catalog.render("imap-mailbox-tree", {
        "host": "10.10.10.10", "port": "993", "username": "bob", "password": "hunter2",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.imap_tree",
        "--host", "10.10.10.10", "--port", "993",
        "--username", "bob", "--password", "hunter2",
    ]


def test_rsync_module_tree_renders_the_list_script_with_the_chosen_module():
    item, command, argv = catalog.render("rsync-module-tree", {
        "host": "10.10.10.10", "port": "873", "path": "backup",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/rsync_tree.sh",
        "10.10.10.10", "873", "backup",
    ]


def test_dotdotpwn_traversal_fuzz_is_listed_with_its_two_user_supplied_variables():
    groups = catalog.list_all()
    http = next(group for group in groups if group["key"] == "http")
    by_id = {command["id"]: command for command in http["commands"]}
    assert by_id["dotdotpwn-traversal-fuzz"]["variables"] == ["match_pattern", "traversal_url"]
    # The command template takes a fully user-supplied URL rather than
    # {host}/{port}/{scheme} tokens the app would fill in itself (the panel
    # prefills a starting URL client-side instead), so this doesn't need the
    # service-selection step needs_service gates other commands behind.
    assert by_id["dotdotpwn-traversal-fuzz"]["needs_service"] is False


def test_dotdotpwn_traversal_fuzz_renders_the_http_url_module():
    item, command, argv = catalog.render("dotdotpwn-traversal-fuzz", {
        "traversal_url": "http://unika.htb/index.php?page=TRAVERSAL",
        "match_pattern": "root:",
    })
    assert argv == [
        "dotdotpwn", "-m", "http-url", "-u", "http://unika.htb/index.php?page=TRAVERSAL",
        "-k", "root:", "-b", "-q",
    ]


def test_dotdotpwn_traversal_fuzz_shell_metacharacters_dont_escape_their_argument():
    # traversal_url/match_pattern are free text the user types in, unlike
    # every other variable here which comes from a dropdown or the target
    # itself -- shlex.quote() has to actually hold for this one.
    item, command, argv = catalog.render("dotdotpwn-traversal-fuzz", {
        "traversal_url": "http://unika.htb/TRAVERSAL; rm -rf ~",
        "match_pattern": "$(whoami)",
    })
    assert argv == [
        "dotdotpwn", "-m", "http-url", "-u", "http://unika.htb/TRAVERSAL; rm -rf ~",
        "-k", "$(whoami)", "-b", "-q",
    ]
    # This app execs argv directly (no shell), so the injection attempt only
    # matters if shlex.split(command) would ever re-tokenize it differently
    # than the original argv -- it must not, since callers only ever use argv.
    assert shlex.split(command) == argv


def test_nfs_export_tree_renders_the_mount_script_with_the_chosen_export_path():
    # showmount -e only lists the exports themselves; this mounts one
    # read-only and walks it for the actual folder/file structure.
    item, command, argv = catalog.render("nfs-export-tree", {
        "host": "10.10.10.10", "path": "/srv/nfs/share",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "bash", "/opt/oscp-workspace/backend/scripts/nfs_tree.sh",
        "10.10.10.10", "/srv/nfs/share",
    ]
    assert item["risk"] == "medium"
