import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

from tyche.modules.profile_generator import (
    HTTPXProfile,
    HTTPXEndpoint,
    HTTPXClient,
    HTTPXServer,
    HTTPXMessage,
    HTTPXTransform
)


@dataclass
class MalleableBlock:
    uri: list[str]
    verb: str
    client_headers: dict[str, str]
    server_headers: dict[str, str]
    client_parameters: dict[str, str]
    message_location: str
    message_name: str
    client_transforms: list[HTTPXTransform]
    server_transforms: list[HTTPXTransform]


class MalleableC2Parser:
    def __init__(self, profile_content: str):
        self.content = profile_content
        self.lines = profile_content.split('\n')

    def parse(self) -> HTTPXProfile:
        profile_name = self._extract_profile_name()
        http_get = self._parse_http_block('http-get', 'GET')
        http_post = self._parse_http_block('http-post', 'POST')

        profile = HTTPXProfile(name=profile_name)

        if http_get:
            profile.get = self._convert_to_endpoint(http_get)

        if http_post:
            profile.post = self._convert_to_endpoint(http_post)

        return profile

    def _extract_profile_name(self) -> str:
        for line in self.lines:
            if line.strip().startswith('#') and 'profile' in line.lower():
                match = re.search(r'#\s*(.+?)\s+(?:profile|browsing)', line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()

        return "Converted Malleable Profile"

    def _parse_http_block(self, block_type: str, verb: str) -> Optional[MalleableBlock]:
        block_content = self._extract_block(block_type)
        if not block_content:
            return None

        uri_list = self._parse_uri(block_content)
        client_content = self._extract_nested_block(block_content, 'client')
        server_content = self._extract_nested_block(block_content, 'server')

        client_headers = self._parse_headers(client_content) if client_content else {}
        server_headers = self._parse_headers(server_content) if server_content else {}
        client_parameters = self._parse_parameters(client_content) if client_content else {}

        message_info = self._parse_message_location(client_content) if client_content else ("cookie", "")
        
        client_transforms = []
        if client_content:
            metadata_transforms = self._parse_transforms(client_content, 'metadata')
            output_transforms = self._parse_transforms(client_content, 'output')
            client_transforms = metadata_transforms if metadata_transforms else output_transforms
        
        server_transforms = self._parse_transforms(server_content, 'output') if server_content else []

        return MalleableBlock(
            uri=uri_list,
            verb=verb,
            client_headers=client_headers,
            server_headers=server_headers,
            client_parameters=client_parameters,
            message_location=message_info[0],
            message_name=message_info[1],
            client_transforms=client_transforms,
            server_transforms=server_transforms
        )

    def _extract_block(self, block_name: str) -> Optional[str]:
        pattern = rf'{block_name}\s*\{{'
        start_match = re.search(pattern, self.content)

        if not start_match:
            return None

        start_pos = start_match.end() - 1
        brace_count = 0
        end_pos = start_pos

        for i in range(start_pos, len(self.content)):
            if self.content[i] == '{':
                brace_count += 1
            elif self.content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i
                    break

        if brace_count == 0:
            return self.content[start_pos + 1:end_pos]
        return None

    def _extract_nested_block(self, content: str, block_name: str) -> Optional[str]:
        pattern = rf'{block_name}\s*\{{'
        start_match = re.search(pattern, content)

        if not start_match:
            return None

        start_pos = start_match.end() - 1
        brace_count = 0
        end_pos = start_pos

        for i in range(start_pos, len(content)):
            if content[i] == '{':
                brace_count += 1
            elif content[i] == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_pos = i
                    break

        if brace_count == 0:
            return content[start_pos + 1:end_pos]
        return None

    @staticmethod
    def _unescape_string(s: str) -> str:
        return s.replace('\\"', '"').replace('\\\\', '\\')

    def _parse_uri(self, content: str) -> list[str]:
        match = re.search(r'set\s+uri\s+"((?:[^"\\]|\\.)*)"', content)
        if match:
            return [self._unescape_string(match.group(1))]

        return ["/"]

    def _parse_headers(self, content: str) -> dict[str, str]:
        headers = {}
        pattern = r'header\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*;'

        for match in re.finditer(pattern, content):
            key = self._unescape_string(match.group(1))
            value = self._unescape_string(match.group(2))
            headers[key] = value

        return headers

    def _parse_parameters(self, content: str) -> dict[str, str]:
        parameters = {}
        pattern = r'parameter\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)"\s*;'

        for match in re.finditer(pattern, content):
            key = self._unescape_string(match.group(1))
            value = self._unescape_string(match.group(2))
            parameters[key] = value

        return parameters

    def _parse_message_location(self, content: str) -> tuple[str, str]:
        # Priority order: output > metadata > id
        # output block is where actual message data goes (especially for POST)
        output_block = self._extract_nested_block(content, 'output')
        metadata_block = self._extract_nested_block(content, 'metadata')
        id_block = self._extract_nested_block(content, 'id')

        # Check output block first (for POST requests)
        if output_block:
            if 'print' in output_block:
                # print means the data goes in the body
                return ("body", "")
            elif 'header "Cookie"' in output_block:
                cookie_name = self._extract_cookie_name(output_block)
                return ("cookie", cookie_name)
            elif 'parameter' in output_block:
                param_match = re.search(r'parameter\s+"([^"]+)"', output_block)
                if param_match:
                    return ("parameter", param_match.group(1))

        # Check metadata block (for GET requests)
        if metadata_block:
            if 'header "Cookie"' in metadata_block:
                cookie_name = self._extract_cookie_name(metadata_block)
                return ("cookie", cookie_name)
            elif 'parameter' in metadata_block:
                param_match = re.search(r'parameter\s+"([^"]+)"', metadata_block)
                if param_match:
                    return ("parameter", param_match.group(1))
            return ("body", "")

        # Fallback to id block (less common)
        if id_block:
            param_match = re.search(r'parameter\s+"([^"]+)"', id_block)
            if param_match:
                return ("parameter", param_match.group(1))

        # Default fallback
        return ("cookie", "__session")

    def _extract_cookie_name(self, metadata_content: str) -> str:
        prepend_matches = re.findall(r'prepend\s+"((?:[^"\\]|\\.)*)"', metadata_content)

        for prepend in prepend_matches:
            prepend = self._unescape_string(prepend)
            if '=' in prepend:
                cookie_name = prepend.split('=')[0].strip(';').strip()
                return cookie_name

        return "__session"

    def _parse_transforms(self, content: str, block_name: str) -> list[HTTPXTransform]:
        transforms = []
        transform_block = self._extract_nested_block(content, block_name)

        if not transform_block:
            return transforms

        lines = [line.strip().rstrip(';') for line in transform_block.split('\n') if line.strip()]

        for line in lines:
            if line.startswith('base64url'):
                transforms.append(HTTPXTransform(action="base64url"))
            elif line.startswith('base64'):
                transforms.append(HTTPXTransform(action="base64"))
            elif line.startswith('prepend'):
                match = re.search(r'prepend\s+"((?:[^"\\]|\\.)*)"', line)
                if match:
                    transforms.append(HTTPXTransform(action="prepend", value=self._unescape_string(match.group(1))))
            elif line.startswith('append'):
                match = re.search(r'append\s+"((?:[^"\\]|\\.)*)"', line)
                if match:
                    transforms.append(HTTPXTransform(action="append", value=self._unescape_string(match.group(1))))
            elif line.startswith('netbiosu'):
                transforms.append(HTTPXTransform(action="netbiosu"))
            elif line.startswith('netbios'):
                transforms.append(HTTPXTransform(action="netbios"))
            elif line.startswith('print'):
                continue

        return transforms

    def _convert_to_endpoint(self, block: MalleableBlock) -> HTTPXEndpoint:
        message = HTTPXMessage(
            location=block.message_location,
            name=block.message_name
        )

        client = HTTPXClient(
            headers=block.client_headers,
            parameters=block.client_parameters if block.client_parameters else None,
            message=message,
            transforms=block.client_transforms if block.client_transforms else None
        )

        server = HTTPXServer(
            headers=block.server_headers,
            transforms=block.server_transforms if block.server_transforms else None
        )

        return HTTPXEndpoint(
            verb=block.verb,
            uris=block.uri,
            client=client,
            server=server
        )


def parse_malleable_profile(profile_content: str, profile_name: Optional[str] = None) -> HTTPXProfile:
    parser = MalleableC2Parser(profile_content)
    profile = parser.parse()

    if profile_name:
        profile.name = profile_name

    return profile


def convert_malleable_file(input_path: Path, output_path: Path, profile_name: Optional[str] = None) -> HTTPXProfile:
    content = input_path.read_text(encoding='utf-8')
    profile = parse_malleable_profile(content, profile_name)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(profile.to_json())

    return profile
