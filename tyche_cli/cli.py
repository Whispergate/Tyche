import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from tyche_cli.modules.burp_parser import parse_burpsuite_request
from tyche_cli.modules.toml_converter import TOMLConverter
from tyche_cli.modules.profile_generator import generate_profile_from_request, HTTPXProfileGenerator
from tyche_cli.modules.malleable_parser import parse_malleable_profile
from tyche_cli.modules.profile_linter import lint_profile_file, Severity
from tyche_cli.modules.rewrite_generator import generate_rewrite_rules

console = Console()
err_console = Console(stderr=True)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='tyche',
        description='Mythic HTTPX Profile Generator - Convert Burpsuite requests, TOML files, and Malleable C2 profiles to HTTPX profiles',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    burp_parser = subparsers.add_parser(
        'burp',
        help='Convert Burpsuite saved request to HTTPX profile'
    )
    burp_parser.add_argument(
        'request_file',
        type=str,
        help='Path to Burpsuite saved request file'
    )
    burp_parser.add_argument(
        '-n', '--name',
        type=str,
        required=True,
        help='Name for the HTTPX profile'
    )
    burp_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: stdout)'
    )

    toml_parser = subparsers.add_parser(
        'toml',
        help='Convert TOML profile to JSON'
    )
    toml_parser.add_argument(
        'toml_file',
        type=str,
        help='Path to TOML profile file'
    )
    toml_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output JSON file path (default: stdout)'
    )

    malleable_parser = subparsers.add_parser(
        'malleable',
        help='Convert Cobalt Strike Malleable C2 profile to HTTPX JSON'
    )
    malleable_parser.add_argument(
        'profile_file',
        type=str,
        help='Path to Malleable C2 profile file'
    )
    malleable_parser.add_argument(
        '-n', '--name',
        type=str,
        help='Override profile name (default: extracted from profile)'
    )
    malleable_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output JSON file path (default: stdout)'
    )

    lint_parser = subparsers.add_parser(
        'lint',
        help='Validate HTTPX profile for errors and issues'
    )
    lint_parser.add_argument(
        'profile_file',
        type=str,
        help='Path to HTTPX profile JSON file to validate'
    )
    lint_parser.add_argument(
        '--strict',
        action='store_true',
        help='Treat warnings as errors'
    )
    lint_parser.add_argument(
        '--quiet',
        action='store_true',
        help='Only show errors and warnings, suppress info messages'
    )

    rewrite_parser = subparsers.add_parser(
        'rewrite',
        help='Generate web server rewrite rules for C2 traffic redirection'
    )
    rewrite_parser.add_argument(
        'profile_file',
        type=str,
        help='Path to HTTPX profile JSON file'
    )
    rewrite_parser.add_argument(
        '-t', '--type',
        type=str,
        required=True,
        choices=['apache2', 'nginx', 'caddy'],
        help='Web server type'
    )
    rewrite_parser.add_argument(
        '-b', '--backend',
        type=str,
        required=True,
        help='Backend C2 server hostname or IP (e.g., 10.10.10.5 or c2.example.com)'
    )
    rewrite_parser.add_argument(
        '-p', '--port',
        type=int,
        default=443,
        help='Backend C2 server port (default: 443)'
    )
    rewrite_parser.add_argument(
        '-s', '--scheme',
        type=str,
        choices=['http', 'https'],
        default='https',
        help='Backend URL scheme (default: https)'
    )
    rewrite_parser.add_argument(
        '--no-user-agent',
        action='store_true',
        help='Do not match User-Agent header (less secure but more flexible)'
    )
    rewrite_parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: stdout)'
    )

    return parser


def handle_burp_command(args: argparse.Namespace) -> int:
    try:
        request_file = Path(args.request_file)
        if not request_file.exists():
            err_console.print(f"[red][-][/red] Error: Request file not found: {args.request_file}")
            return 1

        request_data = request_file.read_text(encoding='utf-8')
        parsed_request = parse_burpsuite_request(request_data)

        generator = HTTPXProfileGenerator(args.name)
        profile = generator.generate_from_burp_request(parsed_request)

        if args.output:
            output_path = Path(args.output)
            generator.save_profile(profile, output_path)
            err_console.print(f"[green][+][/green] Successfully generated HTTPX profile: [cyan]{output_path}[/cyan]")
            err_console.print(f"  [bold]Profile name:[/bold] {profile.name}")
            err_console.print(f"  [bold]Method:[/bold] {parsed_request.method}")
            err_console.print(f"  [bold]URI:[/bold] {parsed_request.uri}")
        else:
            print(profile.to_json())

        return 0

    except Exception as e:
        err_console.print(f"[red][-][/red] Error: {e}")
        return 1


def handle_toml_command(args: argparse.Namespace) -> int:
    try:
        toml_file = Path(args.toml_file)
        if not toml_file.exists():
            err_console.print(f"[red][-][/red] Error: TOML file not found: {args.toml_file}")
            return 1

        if args.output:
            output_path = Path(args.output)
            TOMLConverter.toml_file_to_json_file(toml_file, output_path)
            err_console.print(f"[green][+][/green] Successfully converted TOML to JSON: [cyan]{output_path}[/cyan]")
        else:
            json_output = TOMLConverter.toml_to_json(toml_file.read_text(encoding='utf-8'))
            print(json_output)

        return 0

    except Exception as e:
        err_console.print(f"[red][-][/red] Error: {e}")
        return 1


def handle_malleable_command(args: argparse.Namespace) -> int:
    try:
        profile_file = Path(args.profile_file)
        if not profile_file.exists():
            err_console.print(f"[red][-][/red] Error: Malleable profile not found: {args.profile_file}")
            return 1

        profile_name = args.name if hasattr(args, 'name') and args.name else None
        content = profile_file.read_text(encoding='utf-8')
        profile = parse_malleable_profile(content, profile_name)

        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(profile.to_json())
            err_console.print(f"[green][+][/green] Successfully converted Malleable C2 profile: [cyan]{output_path}[/cyan]")
            err_console.print(f"  [bold]Profile name:[/bold] {profile.name}")
            if profile.get:
                err_console.print(f"  [bold]GET URIs:[/bold] {', '.join(profile.get.uris)}")
            if profile.post:
                err_console.print(f"  [bold]POST URIs:[/bold] {', '.join(profile.post.uris)}")
        else:
            print(profile.to_json())

        return 0

    except Exception as e:
        err_console.print(f"[red][-][/red] Error: {e}")
        return 1


def handle_lint_command(args: argparse.Namespace) -> int:
    try:
        profile_file = Path(args.profile_file)
        if not profile_file.exists():
            console.print(f"[red][-][/red] Error: Profile file not found: {args.profile_file}")
            return 1

        result = lint_profile_file(profile_file)
        
        console.print(f"\n[bold cyan]Linting Profile:[/bold cyan] {profile_file}\n")
        
        if not result.issues:
            console.print(Panel("[green][+] No issues found! Profile is valid.[/green]", style="green"))
            return 0
        
        table = Table(show_header=True, header_style="bold magenta", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Location", style="cyan")
        table.add_column("Message", style="white")
        
        for issue in result.issues:
            if args.quiet and issue.severity == Severity.INFO:
                continue
            
            if issue.severity == Severity.ERROR:
                severity_text = "[red]ERROR[/red]"
            elif issue.severity == Severity.WARNING:
                severity_text = "[yellow]WARNING[/yellow]"
            else:
                severity_text = "[blue]INFO[/blue]"
            
            message = issue.message
            if issue.suggestion:
                message += f"\n[dim]→ {issue.suggestion}[/dim]"
            
            table.add_row(severity_text, issue.location, message)
        
        console.print(table)
        
        summary_text = "[bold]Summary:[/bold] "
        if result.error_count > 0:
            summary_text += f"[red]{result.error_count} error(s)[/red]"
        else:
            summary_text += f"[green]{result.error_count} error(s)[/green]"
        
        summary_text += ", "
        
        if result.warning_count > 0:
            summary_text += f"[yellow]{result.warning_count} warning(s)[/yellow]"
        else:
            summary_text += f"[green]{result.warning_count} warning(s)[/green]"
        
        console.print(f"\n{summary_text}\n")
        
        if result.has_errors:
            console.print(Panel("[red][-] Profile validation FAILED[/red]", style="red"))
            return 1
        elif result.has_warnings and args.strict:
            console.print(Panel("[red][-] Profile validation FAILED (strict mode: warnings treated as errors)[/red]", style="red"))
            return 1
        else:
            console.print(Panel("[green][+] Profile validation PASSED[/green]", style="green"))
            return 0

    except Exception as e:
        console.print(f"[red][-][/red] Error: {e}")
        return 1


def handle_rewrite_command(args: argparse.Namespace) -> int:
    try:
        profile_file = Path(args.profile_file)
        if not profile_file.exists():
            err_console.print(f"[red][-][/red] Error: Profile file not found: {args.profile_file}")
            return 1

        match_user_agent = not args.no_user_agent

        rewrite_config = generate_rewrite_rules(
            profile_path=profile_file,
            server_type=args.type,
            backend_host=args.backend,
            backend_port=args.port,
            backend_scheme=args.scheme,
            match_user_agent=match_user_agent,
            output_path=Path(args.output) if args.output else None
        )

        if args.output:
            err_console.print(f"[green][+][/green] Successfully generated {args.type} rewrite rules: [cyan]{args.output}[/cyan]")
            err_console.print(f"  [bold]Backend:[/bold] {args.scheme}://{args.backend}:{args.port}")
            err_console.print(f"  [bold]User-Agent matching:[/bold] {'Enabled' if match_user_agent else 'Disabled'}")
        else:
            print(rewrite_config)

        return 0

    except Exception as e:
        err_console.print(f"[red][-][/red] Error: {e}")
        return 1


def main() -> int:
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'burp':
        return handle_burp_command(args)
    elif args.command == 'toml':
        return handle_toml_command(args)
    elif args.command == 'malleable':
        return handle_malleable_command(args)
    elif args.command == 'lint':
        return handle_lint_command(args)
    elif args.command == 'rewrite':
        return handle_rewrite_command(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
