from app.imap_tree import parse_list_line


def test_parses_a_plain_unquoted_mailbox_name():
    assert parse_list_line(rb'(\HasNoChildren) "/" INBOX') == ("/", "INBOX")


def test_parses_a_quoted_mailbox_name_with_a_hierarchy_separator():
    assert parse_list_line(rb'(\HasChildren) "/" "INBOX/Sent"') == ("/", "INBOX/Sent")


def test_parses_a_dot_delimited_server():
    assert parse_list_line(rb'(\HasNoChildren) "." "INBOX.Drafts"') == (".", "INBOX.Drafts")


def test_returns_none_for_a_line_that_is_not_a_list_response():
    assert parse_list_line(b"* OK IMAP4rev1 Service Ready") is None


def test_returns_none_for_an_empty_line():
    assert parse_list_line(b"") is None
