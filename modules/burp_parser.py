from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class HTTPRequest:
    method: str
    uri: str
    path: str
    query_params: dict[str, list[str]] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    host: Optional[str] = None


class BurpsuiteRequestParser:
    def __init__(self, request_data: str):
        self.raw_request = request_data
        self.lines = request_data.strip().split('\n')

    def parse(self) -> HTTPRequest:
        request_line = self._parse_request_line()
        headers = self._parse_headers()
        body = self._parse_body()
        cookies = self._extract_cookies(headers)

        parsed_url = urlparse(request_line['uri'])
        query_params = parse_qs(parsed_url.query) if parsed_url.query else {}

        return HTTPRequest(
            method=request_line['method'],
            uri=parsed_url.path or '/',
            path=parsed_url.path or '/',
            query_params=query_params,
            headers=headers,
            cookies=cookies,
            body=body,
            host=headers.get('Host')
        )

    def _parse_request_line(self) -> dict[str, str]:
        if not self.lines:
            raise ValueError("Empty request")

        parts = self.lines[0].strip().split(' ')
        if len(parts) < 2:
            raise ValueError(f"Invalid request line: {self.lines[0]}")

        return {
            'method': parts[0],
            'uri': parts[1],
            'version': parts[2] if len(parts) > 2 else 'HTTP/1.1'
        }

    def _parse_headers(self) -> dict[str, str]:
        headers = {}
        
        for line in self.lines[1:]:
            line = line.strip()
            if not line:
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers

    def _parse_body(self) -> Optional[str]:
        body_start = None
        for i, line in enumerate(self.lines):
            if not line.strip():
                body_start = i + 1
                break

        if body_start and body_start < len(self.lines):
            return '\n'.join(self.lines[body_start:]).strip()

        return None

    def _extract_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        cookie_header = headers.get('Cookie', '')
        if not cookie_header:
            return {}

        cookies = {}
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()

        return cookies


def parse_burpsuite_request(request_data: str) -> HTTPRequest:
    parser = BurpsuiteRequestParser(request_data)
    return parser.parse()
