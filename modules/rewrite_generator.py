"""
Generate web server rewrite rules for C2 traffic redirection.

Supports Apache2, Nginx, and Caddy configurations to redirect matching
C2 profile traffic to the backend C2 server.
"""
import json
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass


@dataclass
class RewriteConfig:
    backend_host: str
    backend_port: int = 443
    backend_scheme: str = "https"
    match_user_agent: bool = True
    default_action: str = "404"  # What to do with non-matching traffic

    @property
    def backend_url(self) -> str:
        return f"{self.backend_scheme}://{self.backend_host}:{self.backend_port}"


class RewriteRuleGenerator:
    """Generate web server rewrite configurations for C2 profiles."""

    def __init__(self, profile_data: dict[str, Any], config: RewriteConfig):
        self.profile = profile_data
        self.config = config

    def _extract_uris(self) -> tuple[list[str], list[str]]:
        """Extract GET and POST URIs from profile."""
        get_uris = []
        post_uris = []

        if "get" in self.profile and "uris" in self.profile["get"]:
            get_uris = self.profile["get"]["uris"]

        if "post" in self.profile and "uris" in self.profile["post"]:
            post_uris = self.profile["post"]["uris"]

        return get_uris, post_uris

    def _extract_user_agent(self) -> Optional[str]:
        """Extract User-Agent from profile if present."""
        # Check GET client headers
        if "get" in self.profile:
            headers = self.profile.get("get", {}).get("client", {}).get("headers", {})
            if "User-Agent" in headers:
                return headers["User-Agent"]

        # Check POST client headers
        if "post" in self.profile:
            headers = self.profile.get("post", {}).get("client", {}).get("headers", {})
            if "User-Agent" in headers:
                return headers["User-Agent"]

        return None

    def generate_apache2(self) -> str:
        """Generate Apache2 mod_rewrite configuration."""
        get_uris, post_uris = self._extract_uris()
        user_agent = self._extract_user_agent()

        lines = [
            "# Apache2 Rewrite Rules for Mythic C2 Profile",
            f"# Profile: {self.profile.get('name', 'Unknown')}",
            f"# Backend: {self.config.backend_url}",
            "",
            "# Enable rewrite engine",
            "RewriteEngine On",
            "",
        ]

        # SSL proxy settings
        lines.extend([
            "# SSL Proxy settings",
            "SSLProxyEngine On",
            "SSLProxyVerify none",
            "SSLProxyCheckPeerCN off",
            "SSLProxyCheckPeerName off",
            "SSLProxyCheckPeerExpire off",
            "",
        ])

        all_uris = list(set(get_uris + post_uris))

        if user_agent and self.config.match_user_agent:
            lines.extend([
                "# Match User-Agent",
                f'RewriteCond %{{HTTP_USER_AGENT}} "^{self._escape_apache_regex(user_agent)}$"',
            ])

        if all_uris:
            lines.append("# Match C2 URIs")
            uri_pattern = "|".join([f"^{self._escape_apache_regex(uri)}$" for uri in all_uris])
            lines.append(f'RewriteCond %{{REQUEST_URI}} "{uri_pattern}"')

        lines.extend([
            f"RewriteRule ^(.*)$ {self.config.backend_url}/$1 [P,L]",
            "",
        ])

        if self.config.default_action == "404":
            lines.extend([
                "# Return 404 for non-matching requests",
                "RewriteRule ^.*$ - [R=404,L]",
            ])

        return "\n".join(lines)

    def generate_nginx(self) -> str:
        """Generate Nginx rewrite configuration."""
        get_uris, post_uris = self._extract_uris()
        user_agent = self._extract_user_agent()

        lines = [
            "# Nginx Configuration for Mythic C2 Profile",
            f"# Profile: {self.profile.get('name', 'Unknown')}",
            f"# Backend: {self.config.backend_url}",
            "",
            "# Place this inside your server {} block",
            "",
        ]

        # Set variable for matching
        lines.extend([
            "# Initialize match variable",
            "set $c2_match 0;",
            "",
        ])

        # Match User-Agent if specified
        if user_agent and self.config.match_user_agent:
            lines.extend([
                "# Match User-Agent",
                f'if ($http_user_agent = "{user_agent}") {{',
                "    set $c2_match 1;",
                "}",
                "",
            ])
        else:
            lines.extend([
                "# No User-Agent matching",
                "set $c2_match 1;",
                "",
            ])

        # Create location blocks for each URI
        all_uris = list(set(get_uris + post_uris))
        
        if all_uris:
            lines.append("# C2 URI endpoints")
            for uri in all_uris:
                lines.extend([
                    f"location = {uri} {{",
                    "    if ($c2_match = 0) {",
                    "        return 404;",
                    "    }",
                    f"    proxy_pass {self.config.backend_url};",
                    "    proxy_set_header Host $host;",
                    "    proxy_set_header X-Real-IP $remote_addr;",
                    "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
                    "    proxy_set_header X-Forwarded-Proto $scheme;",
                    "    proxy_ssl_verify off;",
                    "}",
                    "",
                ])

        if self.config.default_action == "404":
            lines.extend([
                "# Default action for non-matching URIs",
                "location / {",
                "    return 404;",
                "}",
            ])

        return "\n".join(lines)

    def generate_caddy(self) -> str:
        """Generate Caddy configuration."""
        get_uris, post_uris = self._extract_uris()
        user_agent = self._extract_user_agent()

        lines = [
            "# Caddy Configuration for Mythic C2 Profile",
            f"# Profile: {self.profile.get('name', 'Unknown')}",
            f"# Backend: {self.config.backend_url}",
            "",
            "# Place this inside your site block",
            "",
        ]

        all_uris = list(set(get_uris + post_uris))

        if all_uris:
            for uri in all_uris:
                lines.append(f"route {uri} {{")

                if user_agent and self.config.match_user_agent:
                    lines.extend([
                        f'    @c2agent header User-Agent "{user_agent}"',
                        "    reverse_proxy @c2agent {",
                        f"        to {self.config.backend_url}",
                        "        transport http {",
                        "            tls_insecure_skip_verify",
                        "        }",
                        "    }",
                        "",
                        "    respond 404",
                    ])
                else:
                    lines.extend([
                        "    reverse_proxy {",
                        f"        to {self.config.backend_url}",
                        "        transport http {",
                        "            tls_insecure_skip_verify",
                        "        }",
                        "    }",
                    ])

                lines.extend([
                    "}",
                    "",
                ])

        if self.config.default_action == "404":
            lines.extend([
                "# Default action",
                "route {",
                "    respond 404",
                "}",
            ])

        return "\n".join(lines)

    @staticmethod
    def _escape_apache_regex(text: str) -> str:
        """Escape special characters for Apache regex."""
        special_chars = r'\.^$*+?()[]{}|'
        escaped = text
        for char in special_chars:
            escaped = escaped.replace(char, '\\' + char)
        return escaped


def generate_rewrite_rules(
    profile_path: Path,
    server_type: str,
    backend_host: str,
    backend_port: int = 443,
    backend_scheme: str = "https",
    match_user_agent: bool = True,
    output_path: Optional[Path] = None
) -> str:
    """
    Generate web server rewrite rules from a C2 profile.

    Args:
        profile_path: Path to the HTTPX profile JSON file
        server_type: Type of server ('apache2', 'nginx', 'caddy')
        backend_host: Backend C2 server hostname or IP
        backend_port: Backend C2 server port
        backend_scheme: Backend scheme ('http' or 'https')
        match_user_agent: Whether to match User-Agent header
        output_path: Optional path to save the configuration

    Returns:
        Generated configuration as a string
    """
    with open(profile_path, 'r', encoding='utf-8') as f:
        profile_data = json.load(f)

    config = RewriteConfig(
        backend_host=backend_host,
        backend_port=backend_port,
        backend_scheme=backend_scheme,
        match_user_agent=match_user_agent
    )

    generator = RewriteRuleGenerator(profile_data, config)

    if server_type.lower() == "apache2":
        result = generator.generate_apache2()
    elif server_type.lower() == "nginx":
        result = generator.generate_nginx()
    elif server_type.lower() == "caddy":
        result = generator.generate_caddy()
    else:
        raise ValueError(f"Unknown server type: {server_type}. Must be 'apache2', 'nginx', or 'caddy'")

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result, encoding='utf-8')

    return result
