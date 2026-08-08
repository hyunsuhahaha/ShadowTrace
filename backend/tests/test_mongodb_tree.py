from app.mongodb_tree import build_tree_lines


class FakeDatabase:
    def __init__(self, collections):
        self._collections = collections

    def list_collection_names(self):
        return self._collections


class FakeMongoClient:
    def __init__(self, databases):
        self._databases = databases

    def list_database_names(self):
        return list(self._databases.keys())

    def __getitem__(self, name):
        return FakeDatabase(self._databases[name])


def test_lists_databases_and_collections_as_a_tree():
    client = FakeMongoClient({
        "app_db": ["users", "orders"],
        "logs_db": ["access_log"],
    })
    assert build_tree_lines(client) == [
        "D|app_db", "F|app_db/orders", "F|app_db/users",
        "D|logs_db", "F|logs_db/access_log",
    ]


def test_skips_system_databases():
    client = FakeMongoClient({
        "admin": ["system.version"], "local": ["startup_log"], "config": ["settings"],
        "app_db": ["users"],
    })
    assert build_tree_lines(client) == ["D|app_db", "F|app_db/users"]


def test_returns_an_empty_tree_for_a_server_with_no_user_databases():
    client = FakeMongoClient({"admin": ["system.version"]})
    assert build_tree_lines(client) == []
