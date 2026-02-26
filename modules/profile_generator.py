import json
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass

from modules.burp_parser import HTTPRequest


@dataclass
class HTTPXTransform:
    action: str
    value: str = ""


@dataclass
class HTTPXMessage:
    location: str
    name: str = ""


@dataclass
class HTTPXClient:
    headers: dict[str, str]
    parameters: Optional[dict[str, str]] = None
    message: Optional[HTTPXMessage] = None
    transforms: Optional[list[HTTPXTransform]] = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"headers": self.headers}
        if self.parameters:
            result["parameters"] = self.parameters
        else:
            result["parameters"] = None

        if self.message:
            result["message"] = {
                "location": self.message.location,
                "name": self.message.name
            }

        if self.transforms:
            result["transforms"] = [
                {"action": t.action, "value": t.value}
                for t in self.transforms
            ]

        return result


@dataclass
class HTTPXServer:
    headers: dict[str, str]
    transforms: Optional[list[HTTPXTransform]] = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"headers": self.headers}

        if self.transforms:
            result["transforms"] = [
                {"action": t.action, "value": t.value}
                for t in self.transforms
            ]

        return result


@dataclass
class HTTPXEndpoint:
    verb: str
    uris: list[str]
    client: HTTPXClient
    server: HTTPXServer

    def to_dict(self) -> dict[str, Any]:
        return {
            "verb": self.verb,
            "uris": self.uris,
            "client": self.client.to_dict(),
            "server": self.server.to_dict()
        }


@dataclass
class HTTPXProfile:
    name: str
    get: Optional[HTTPXEndpoint] = None
    post: Optional[HTTPXEndpoint] = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"name": self.name}

        if self.get:
            result["get"] = self.get.to_dict()

        if self.post:
            result["post"] = self.post.to_dict()

        return result

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class HTTPXProfileGenerator:
    def __init__(self, profile_name: str):
        self.profile_name = profile_name

    def generate_from_burp_request(
        self,
        request: HTTPRequest,
        default_server_headers: Optional[dict[str, str]] = None,
        default_transforms: Optional[list[HTTPXTransform]] = None
    ) -> HTTPXProfile:
        client_headers = self._filter_headers(request.headers)

        query_params = None
        if request.query_params:
            query_params = {k: v[0] for k, v in request.query_params.items()}

        message_location = self._determine_message_location(request)
        message = HTTPXMessage(
            location=message_location["location"],
            name=message_location.get("name", "")
        )

        transforms = default_transforms or [HTTPXTransform(action="base64url")]

        client = HTTPXClient(
            headers=client_headers,
            parameters=query_params,
            message=message,
            transforms=transforms
        )

        server_headers = default_server_headers or self._get_default_server_headers()
        server = HTTPXServer(
            headers=server_headers,
            transforms=transforms
        )

        endpoint = HTTPXEndpoint(
            verb=request.method,
            uris=[request.uri],
            client=client,
            server=server
        )

        profile = HTTPXProfile(name=self.profile_name)

        if request.method.upper() == "GET":
            profile.get = endpoint
        elif request.method.upper() == "POST":
            profile.post = endpoint
        else:
            profile.get = endpoint

        return profile

    def _filter_headers(self, headers: dict[str, str]) -> dict[str, str]:
        excluded_headers = {
            'Content-Length',
            'Transfer-Encoding',
            'Cookie'
        }

        return {
            k: v for k, v in headers.items()
            if k not in excluded_headers
        }

    def _determine_message_location(self, request: HTTPRequest) -> dict[str, str]:
        if request.cookies:
            cookie_name = list(request.cookies.keys())[0]
            return {"location": "cookie", "name": cookie_name}

        if request.body:
            return {"location": "body", "name": ""}

        if request.query_params:
            param_name = list(request.query_params.keys())[0]
            return {"location": "parameter", "name": param_name}

        return {"location": "cookie", "name": "__session"}

    def _get_default_server_headers(self) -> dict[str, str]:
        return {
            "Server": "nginx/1.18.0",
            "Cache-Control": "max-age=0, no-cache",
            "Connection": "keep-alive"
        }

    def save_profile(self, profile: HTTPXProfile, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(profile.to_json())


def generate_profile_from_request(
    request: HTTPRequest,
    profile_name: str,
    output_path: Optional[Path] = None
) -> HTTPXProfile:
    generator = HTTPXProfileGenerator(profile_name)
    profile = generator.generate_from_burp_request(request)

    if output_path:
        generator.save_profile(profile, output_path)

    return profile
