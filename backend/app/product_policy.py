"""Central product boundary shared by API, UI, tests, and future modules."""

PRIORITY = [
    "scan_center",
    "service_enumeration",
    "web_testing_workspace",
    "evidence_management",
]

ALLOWED_CAPABILITIES = [
    "information_collection_and_organization",
    "static_command_templates",
    "user_selected_enumeration_execution",
    "result_parsing_and_visualization",
    "user_authored_http_request_replay",
]

PROHIBITED_CAPABILITIES = [
    "automatic_vulnerability_determination",
    "automatic_exploit_selection_or_execution",
    "large_scale_vulnerability_scanning",
    "automatic_shell_acquisition",
    "ai_analysis",
    "spoofing",
]

def public_policy() -> dict[str, list[str]]:
    return {
        "priority": PRIORITY,
        "allowed": ALLOWED_CAPABILITIES,
        "prohibited": PROHIBITED_CAPABILITIES,
    }
