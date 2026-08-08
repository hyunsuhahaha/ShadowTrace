import ldap3
from ldap3 import MOCK_SYNC, Connection, Server

from app.ldap_tree import dn_to_path, walk


def _mock_connection() -> Connection:
    connection = Connection(Server("fake"), client_strategy=MOCK_SYNC)
    connection.strategy.add_entry(
        "dc=corp,dc=local", {"objectClass": ["top", "domain"]})
    connection.strategy.add_entry(
        "ou=Users,dc=corp,dc=local", {"objectClass": ["top", "organizationalUnit"]})
    connection.strategy.add_entry(
        "cn=user1,ou=Users,dc=corp,dc=local",
        {"objectClass": ["top", "person"], "cn": "user1"})
    connection.strategy.add_entry(
        "cn=user2,ou=Users,dc=corp,dc=local",
        {"objectClass": ["top", "person"], "cn": "user2"})
    connection.bind()
    return connection


def test_dn_to_path_reverses_components_and_excludes_the_base_dn_itself():
    assert dn_to_path("dc=corp,dc=local", "dc=corp,dc=local") is None
    assert dn_to_path("cn=user1,ou=Users,dc=corp,dc=local", "dc=corp,dc=local") == (
        "dc=local/dc=corp/ou=Users/cn=user1")


def test_dn_to_path_matches_the_base_dn_case_insensitively():
    assert dn_to_path("DC=Corp,DC=Local", "dc=corp,dc=local") is None


def test_walk_tags_every_entry_under_the_base_dn_as_a_leaf():
    connection = _mock_connection()
    lines = walk(connection, "dc=corp,dc=local")
    assert sorted(lines) == [
        "F|dc=local/dc=corp/ou=Users",
        "F|dc=local/dc=corp/ou=Users/cn=user1",
        "F|dc=local/dc=corp/ou=Users/cn=user2",
    ]
