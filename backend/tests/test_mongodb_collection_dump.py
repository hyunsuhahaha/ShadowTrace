from app.mongodb_collection_dump import dump_collection


class FakeCursor:
    def __init__(self, docs):
        self._docs = docs

    def limit(self, n):
        return list(self._docs)[:n]


class FakeCollection:
    def __init__(self, docs):
        self._docs = docs

    def find(self):
        return FakeCursor(self._docs)


class FakeDatabase:
    def __init__(self, collections):
        self._collections = collections

    def __getitem__(self, name):
        return FakeCollection(self._collections[name])


class FakeMongoClient:
    def __init__(self, databases):
        self._databases = databases

    def __getitem__(self, name):
        return FakeDatabase(self._databases[name])


def test_dumps_every_document_in_the_named_collection():
    client = FakeMongoClient({
        "ace": {"admin": [
            {"name": "admin", "x_shadow": "$2a$10$fakehash"},
        ]},
    })
    assert dump_collection(client, "ace", "admin", limit=20) == [
        {"name": "admin", "x_shadow": "$2a$10$fakehash"},
    ]


def test_respects_the_document_limit():
    client = FakeMongoClient({
        "app_db": {"users": [{"id": i} for i in range(50)]},
    })
    assert len(dump_collection(client, "app_db", "users", limit=5)) == 5
