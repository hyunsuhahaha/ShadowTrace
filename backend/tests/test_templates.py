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


def test_list_all_skips_groups_with_no_commands():
    groups = catalog.list_all()
    assert all(group["commands"] for group in groups)


def test_tool_catalog_endpoint_wraps_list_all_under_a_groups_key():
    body = tool_catalog()
    assert body["groups"] == catalog.list_all()
