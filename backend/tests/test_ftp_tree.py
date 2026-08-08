import ftplib

from app.ftp_tree import walk


class FakeMlsdFtp:
    """A server that supports MLSD -- the common/modern case."""
    tree = {
        "": [("pub", True), ("readme.txt", False)],
        "pub": [("notes.txt", False), ("backups", True)],
        "pub/backups": [("site.zip", False)],
    }

    def mlsd(self, path):
        return [(name, {"type": "dir" if is_dir else "file"})
                for name, is_dir in self.tree[path]]


class FakeListOnlyFtp:
    """A server old enough to only support LIST (e.g. some IIS FTP)."""
    tree = {
        "": [
            "drwxr-xr-x    2 ftp      ftp          4096 Jan 01 00:00 pub",
            "-rw-r--r--    1 ftp      ftp           128 Jan 01 00:00 readme.txt",
        ],
        "pub": [
            "-rw-r--r--    1 ftp      ftp           256 Jan 01 00:00 notes.txt",
        ],
    }

    def mlsd(self, path):
        raise ftplib.error_perm("502 Command not implemented")

    def retrlines(self, cmd, callback):
        _, path = cmd.split(" ", 1)
        for line in self.tree[path]:
            callback(line)


def test_walk_tags_directories_and_files_via_mlsd():
    lines = walk(FakeMlsdFtp(), "", 0, [2000])
    assert lines == [
        "D|pub", "D|pub/backups", "F|pub/backups/site.zip", "F|pub/notes.txt",
        "F|readme.txt",
    ]


def test_walk_falls_back_to_list_parsing_when_mlsd_is_unsupported():
    lines = walk(FakeListOnlyFtp(), "", 0, [2000])
    assert lines == ["D|pub", "F|pub/notes.txt", "F|readme.txt"]


def test_walk_stops_at_the_entry_budget():
    lines = walk(FakeMlsdFtp(), "", 0, [2])
    assert lines == ["D|pub", "D|pub/backups"]
