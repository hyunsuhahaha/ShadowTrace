from app.cloud_storage_probe import classify_provider
from app.templates import catalog as command_catalog

ACCESS_DENIED_XML = "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"


def test_classifies_real_aws_s3_by_the_amazon_server_header():
    result = classify_provider(
        {"Server": "AmazonS3", "x-amz-request-id": "ABC123"}, ACCESS_DENIED_XML)
    assert result["provider"] == "aws-s3"
    assert result["error_code"] == "AccessDenied"


def test_classifies_minio_separately_from_real_aws_despite_shared_amz_headers():
    # MinIO emulates the x-amz-* header family for S3 API compatibility, so
    # the Server header is what actually tells the two apart.
    result = classify_provider(
        {"Server": "MinIO", "x-amz-request-id": "ABC123"}, ACCESS_DENIED_XML)
    assert result["provider"] == "minio (s3-compatible)"


def test_classifies_unbranded_s3_compatible_backend_by_amz_headers_alone():
    result = classify_provider({"x-amz-bucket-region": "us-east-1"}, ACCESS_DENIED_XML)
    assert result["provider"] == "s3-compatible (Server: unset)"


def test_classifies_azure_blob_storage_by_ms_headers():
    result = classify_provider(
        {"Server": "Windows-Azure-Blob/1.0", "x-ms-request-id": "abc"},
        "<Error><Code>ResourceNotFound</Code><Message>x</Message></Error>")
    assert result["provider"] == "azure-blob-storage"


def test_classifies_google_cloud_storage_by_goog_headers():
    result = classify_provider(
        {"Server": "UploadServer", "x-goog-hash": "crc32c=abc"}, ACCESS_DENIED_XML)
    assert result["provider"] == "google-cloud-storage"


def test_falls_back_to_request_id_and_host_id_when_headers_are_stripped():
    # A reverse proxy can strip the x-amz-*/Server headers but the body is
    # rendered by the storage backend itself, so RequestId+HostId survives.
    body = "<Error><Code>AccessDenied</Code><RequestId>r1</RequestId><HostId>h1</HostId></Error>"
    result = classify_provider({}, body)
    assert result["provider"].startswith("likely-s3-compatible")


def test_unknown_when_nothing_matches():
    result = classify_provider({}, "<html>not a storage error</html>")
    assert result["provider"] == "unknown"
    assert result["error_code"] is None


def test_cloud_storage_fingerprint_command_appears_in_the_generic_http_list():
    # Unlike vhost/param fuzzing, this needs no extra input beyond
    # host/port/scheme, so it stays in the auto-populated list.
    commands = {item["id"] for item in command_catalog.commands_for("http", 80)}
    assert "cloud-storage-fingerprint" in commands
    _, command, argv = command_catalog.render("cloud-storage-fingerprint", {
        "host": "10.10.11.80", "port": "80", "scheme": "http",
        "repo_dir": "/opt/oscp-workspace",
    })
    assert argv == [
        "/opt/oscp-workspace/.venv/bin/python", "-m", "app.cloud_storage_probe",
        "--host", "10.10.11.80", "--port", "80", "--scheme", "http",
    ]
