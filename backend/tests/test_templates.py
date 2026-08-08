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
