import json
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class LintIssue:
    severity: Severity
    message: str
    location: str
    suggestion: Optional[str] = None

    def __str__(self) -> str:
        result = f"[{self.severity.value}] {self.location}: {self.message}"
        if self.suggestion:
            result += f"\n  Suggestion: {self.suggestion}"
        return result


@dataclass
class LintResult:
    issues: list[LintIssue] = field(default_factory=list)

    def add_error(self, message: str, location: str, suggestion: Optional[str] = None) -> None:
        self.issues.append(LintIssue(Severity.ERROR, message, location, suggestion))

    def add_warning(self, message: str, location: str, suggestion: Optional[str] = None) -> None:
        self.issues.append(LintIssue(Severity.WARNING, message, location, suggestion))

    def add_info(self, message: str, location: str, suggestion: Optional[str] = None) -> None:
        self.issues.append(LintIssue(Severity.INFO, message, location, suggestion))

    @property
    def has_errors(self) -> bool:
        return any(issue.severity == Severity.ERROR for issue in self.issues)

    @property
    def has_warnings(self) -> bool:
        return any(issue.severity == Severity.WARNING for issue in self.issues)

    @property
    def error_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for issue in self.issues if issue.severity == Severity.WARNING)

    @property
    def is_valid(self) -> bool:
        return not self.has_errors


class HTTPXProfileLinter:
    VALID_VERBS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
    VALID_MESSAGE_LOCATIONS = {"cookie", "body", "parameter", "uri", "header"}
    VALID_TRANSFORM_ACTIONS = {"base64", "base64url", "prepend", "append", "xor", "netbios", "netbiosu"}

    REQUIRED_HEADER_FIELDS = {"User-Agent"}
    SUSPICIOUS_HEADERS = {
        "Content-Length": "Content-Length should not be manually set",
        "Transfer-Encoding": "Transfer-Encoding should not be manually set",
    }

    def __init__(self, profile: dict[str, Any]):
        self.profile = profile
        self.result = LintResult()

    def lint(self) -> LintResult:
        self._check_profile_structure()
        self._check_profile_name()

        if "get" in self.profile:
            self._check_endpoint(self.profile["get"], "get")

        if "post" in self.profile:
            self._check_endpoint(self.profile["post"], "post")

        if "get" not in self.profile and "post" not in self.profile:
            self.result.add_error(
                "Profile must contain at least one endpoint (get or post)",
                "profile",
                "Add either a 'get' or 'post' endpoint configuration"
            )

        return self.result

    def _check_profile_structure(self) -> None:
        if not isinstance(self.profile, dict):
            self.result.add_error("Profile must be a JSON object", "profile")
            return

        if "name" not in self.profile:
            self.result.add_error("Profile missing required 'name' field", "profile")

    def _check_profile_name(self) -> None:
        if "name" in self.profile:
            name = self.profile["name"]
            if not isinstance(name, str):
                self.result.add_error("Profile name must be a string", "profile.name")
            elif not name.strip():
                self.result.add_error("Profile name cannot be empty", "profile.name")
            elif len(name) > 100:
                self.result.add_warning(
                    f"Profile name is very long ({len(name)} characters)",
                    "profile.name",
                    "Consider using a shorter, more concise name"
                )

    def _check_endpoint(self, endpoint: dict[str, Any], endpoint_name: str) -> None:
        location = f"profile.{endpoint_name}"

        if not isinstance(endpoint, dict):
            self.result.add_error(f"Endpoint must be a JSON object", location)
            return

        self._check_verb(endpoint, location)
        self._check_uris(endpoint, location)
        self._check_client_section(endpoint.get("client"), location)
        self._check_server_section(endpoint.get("server"), location)

    def _check_verb(self, endpoint: dict[str, Any], location: str) -> None:
        if "verb" not in endpoint:
            self.result.add_error("Endpoint missing required 'verb' field", location)
            return

        verb = endpoint["verb"]
        if not isinstance(verb, str):
            self.result.add_error("Verb must be a string", f"{location}.verb")
        elif verb.upper() not in self.VALID_VERBS:
            self.result.add_error(
                f"Invalid HTTP verb: {verb}",
                f"{location}.verb",
                f"Valid verbs: {', '.join(self.VALID_VERBS)}"
            )
        elif verb != verb.upper():
            self.result.add_warning(
                f"HTTP verb should be uppercase: {verb}",
                f"{location}.verb",
                f"Use '{verb.upper()}' instead"
            )

    def _check_uris(self, endpoint: dict[str, Any], location: str) -> None:
        if "uris" not in endpoint:
            self.result.add_error("Endpoint missing required 'uris' field", location)
            return

        uris = endpoint["uris"]
        if not isinstance(uris, list):
            self.result.add_error("URIs must be an array", f"{location}.uris")
            return

        if not uris:
            self.result.add_error("URIs array cannot be empty", f"{location}.uris")
            return

        for i, uri in enumerate(uris):
            if not isinstance(uri, str):
                self.result.add_error(
                    f"URI at index {i} must be a string",
                    f"{location}.uris[{i}]"
                )
            elif not uri.startswith("/"):
                self.result.add_warning(
                    f"URI should start with '/': {uri}",
                    f"{location}.uris[{i}]",
                    f"Consider changing to '/{uri}'"
                )
            elif " " in uri:
                self.result.add_warning(
                    f"URI contains spaces: {uri}",
                    f"{location}.uris[{i}]",
                    "Spaces should be URL-encoded as %20"
                )

    def _check_client_section(self, client: Optional[dict[str, Any]], location: str) -> None:
        client_location = f"{location}.client"

        if client is None:
            self.result.add_error("Endpoint missing required 'client' section", location)
            return

        if not isinstance(client, dict):
            self.result.add_error("Client section must be a JSON object", client_location)
            return

        self._check_headers(client.get("headers"), client_location, is_client=True)
        self._check_parameters(client.get("parameters"), client_location)
        self._check_message(client.get("message"), client_location)
        self._check_transforms(client.get("transforms"), client_location, is_client=True)

    def _check_server_section(self, server: Optional[dict[str, Any]], location: str) -> None:
        server_location = f"{location}.server"

        if server is None:
            self.result.add_error("Endpoint missing required 'server' section", location)
            return

        if not isinstance(server, dict):
            self.result.add_error("Server section must be a JSON object", server_location)
            return

        self._check_headers(server.get("headers"), server_location, is_client=False)
        self._check_transforms(server.get("transforms"), server_location, is_client=False)

    def _check_headers(self, headers: Optional[dict[str, str]], location: str, is_client: bool) -> None:
        headers_location = f"{location}.headers"

        if headers is None:
            self.result.add_warning("Missing headers section", location)
            return

        if not isinstance(headers, dict):
            self.result.add_error("Headers must be a JSON object", headers_location)
            return

        if not headers:
            self.result.add_warning("Headers section is empty", headers_location)

        if is_client:
            for required_header in self.REQUIRED_HEADER_FIELDS:
                if required_header not in headers:
                    self.result.add_warning(
                        f"Missing recommended header: {required_header}",
                        headers_location,
                        f"Add a '{required_header}' header for better blending"
                    )

        for header_name, header_value in headers.items():
            if header_name in self.SUSPICIOUS_HEADERS:
                self.result.add_warning(
                    self.SUSPICIOUS_HEADERS[header_name],
                    f"{headers_location}.{header_name}"
                )

            if not isinstance(header_value, str):
                self.result.add_error(
                    f"Header value must be a string",
                    f"{headers_location}.{header_name}"
                )
            elif not header_value.strip():
                self.result.add_warning(
                    f"Header value is empty",
                    f"{headers_location}.{header_name}"
                )

    def _check_parameters(self, parameters: Optional[dict[str, str]], location: str) -> None:
        if parameters is None:
            return

        params_location = f"{location}.parameters"

        if not isinstance(parameters, dict):
            self.result.add_error("Parameters must be a JSON object", params_location)
            return

        for param_name, param_value in parameters.items():
            if not isinstance(param_value, str):
                self.result.add_warning(
                    f"Parameter value should be a string",
                    f"{params_location}.{param_name}"
                )

    def _check_message(self, message: Optional[dict[str, str]], location: str) -> None:
        message_location = f"{location}.message"

        if message is None:
            self.result.add_info("No message configuration specified", location)
            return

        if not isinstance(message, dict):
            self.result.add_error("Message must be a JSON object", message_location)
            return

        if "location" not in message:
            self.result.add_error("Message missing required 'location' field", message_location)
            return

        msg_location = message["location"]
        if msg_location not in self.VALID_MESSAGE_LOCATIONS:
            self.result.add_error(
                f"Invalid message location: {msg_location}",
                f"{message_location}.location",
                f"Valid locations: {', '.join(self.VALID_MESSAGE_LOCATIONS)}"
            )

        if "name" not in message:
            self.result.add_warning(
                "Message missing 'name' field",
                message_location,
                "Specify a name for the message parameter/cookie/header"
            )
        elif not isinstance(message["name"], str):
            self.result.add_error(
                "Message name must be a string",
                f"{message_location}.name"
            )
        elif msg_location in {"cookie", "parameter", "header"} and not message["name"].strip():
            self.result.add_error(
                f"Message name cannot be empty for location '{msg_location}'",
                f"{message_location}.name"
            )

    def _check_transforms(self, transforms: Optional[list[dict[str, str]]], location: str, is_client: bool) -> None:
        if transforms is None:
            self.result.add_info("No transforms specified", location)
            return

        transforms_location = f"{location}.transforms"

        if not isinstance(transforms, list):
            self.result.add_error("Transforms must be an array", transforms_location)
            return

        if not transforms:
            self.result.add_warning("Transforms array is empty", transforms_location)
            return

        encoding_count = 0
        for i, transform in enumerate(transforms):
            if not isinstance(transform, dict):
                self.result.add_error(
                    f"Transform at index {i} must be a JSON object",
                    f"{transforms_location}[{i}]"
                )
                continue

            if "action" not in transform:
                self.result.add_error(
                    "Transform missing required 'action' field",
                    f"{transforms_location}[{i}]"
                )
                continue

            action = transform["action"]
            if action not in self.VALID_TRANSFORM_ACTIONS:
                self.result.add_error(
                    f"Invalid transform action: {action}",
                    f"{transforms_location}[{i}].action",
                    f"Valid actions: {', '.join(self.VALID_TRANSFORM_ACTIONS)}"
                )

            if action in {"base64", "base64url"}:
                encoding_count += 1

            if action in {"prepend", "append", "xor"} and "value" not in transform:
                self.result.add_error(
                    f"Transform '{action}' requires a 'value' field",
                    f"{transforms_location}[{i}]"
                )
            elif action in {"prepend", "append", "xor"} and not transform.get("value"):
                self.result.add_warning(
                    f"Transform '{action}' has empty value",
                    f"{transforms_location}[{i}].value"
                )

        if encoding_count > 1:
            self.result.add_warning(
                f"Multiple encoding transforms ({encoding_count}) found",
                transforms_location,
                "Multiple encoding may cause issues"
            )

        if is_client and encoding_count == 0:
            self.result.add_info(
                "No encoding transform specified",
                transforms_location,
                "Consider adding base64 or base64url encoding"
            )


def lint_profile(profile_data: dict[str, Any]) -> LintResult:
    linter = HTTPXProfileLinter(profile_data)
    return linter.lint()


def lint_profile_file(profile_path: Path) -> LintResult:
    try:
        with open(profile_path, 'r', encoding='utf-8') as f:
            profile_data = json.load(f)

        return lint_profile(profile_data)
    except json.JSONDecodeError as e:
        result = LintResult()
        result.add_error(
            f"Invalid JSON: {e.msg}",
            f"line {e.lineno}, column {e.colno}",
            "Ensure the file is valid JSON"
        )
        return result
    except Exception as e:
        result = LintResult()
        result.add_error(f"Failed to read file: {e}", str(profile_path))
        return result
