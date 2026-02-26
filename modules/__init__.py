from modules.burp_parser import parse_burpsuite_request, BurpsuiteRequestParser, HTTPRequest
from modules.toml_converter import convert_toml_to_json, TOMLConverter
from modules.profile_generator import (
    generate_profile_from_request,
    HTTPXProfileGenerator,
    HTTPXProfile,
    HTTPXEndpoint,
    HTTPXClient,
    HTTPXServer,
    HTTPXMessage,
    HTTPXTransform
)
from modules.malleable_parser import parse_malleable_profile, convert_malleable_file, MalleableC2Parser
from modules.profile_linter import lint_profile, lint_profile_file, HTTPXProfileLinter, LintResult, LintIssue, Severity
from modules.rewrite_generator import generate_rewrite_rules, RewriteRuleGenerator, RewriteConfig

__all__ = [
    'parse_burpsuite_request',
    'BurpsuiteRequestParser',
    'HTTPRequest',
    'convert_toml_to_json',
    'TOMLConverter',
    'generate_profile_from_request',
    'HTTPXProfileGenerator',
    'HTTPXProfile',
    'HTTPXEndpoint',
    'HTTPXClient',
    'HTTPXServer',
    'HTTPXMessage',
    'HTTPXTransform',
    'parse_malleable_profile',
    'convert_malleable_file',
    'MalleableC2Parser',
    'lint_profile',
    'lint_profile_file',
    'HTTPXProfileLinter',
    'LintResult',
    'LintIssue',
    'Severity',
    'generate_rewrite_rules',
    'RewriteRuleGenerator',
    'RewriteConfig',
]
