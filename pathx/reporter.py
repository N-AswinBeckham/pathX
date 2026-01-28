import os
import sys
from typing import List, Dict

from .scanner import Finding, ScanResult


class Colors:
    """ANSI color codes."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"

    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)."""
        cls.RESET = cls.BOLD = cls.RED = cls.GREEN = ""
        cls.YELLOW = cls.BLUE = cls.CYAN = ""


def supports_color() -> bool:
    """Check if terminal supports colors."""
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get('NO_COLOR'):
        return False
    return True


def make_hyperlink(file_path: str, line: int, text: str) -> str:
    """
    Create OSC 8 hyperlink for terminal.
    Clicking opens file:line in default editor.
    """
    abs_path = os.path.abspath(file_path)
    url = f"file://{abs_path}:{line}"
    # OSC 8 format: \e]8;;URL\e\\TEXT\e]8;;\e\\
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def print_progress(files_scanned: int, current_file: str):
    """Print scanning progress (updates in place)."""
    display_file = current_file
    if len(display_file) > 50:
        display_file = "..." + display_file[-47:]
    sys.stdout.write(f"\r{Colors.CYAN}Scanning...{Colors.RESET} {files_scanned} files  ")
    sys.stdout.flush()


def clear_progress():
    """Clear the progress line."""
    sys.stdout.write("\r" + " " * 70 + "\r")
    sys.stdout.flush()


def print_results(result: ScanResult, directory: str):
    """Print scan results to terminal."""
    if not supports_color():
        Colors.disable()

    clear_progress()

    # Header
    print(f"\n{Colors.BOLD}PathX - Hardcoded Path Detector{Colors.RESET}")
    print(f"Scanned: {os.path.abspath(directory)}")
    print("\u2501" * 50)

    if not result.findings:
        print(f"\n{Colors.GREEN}\u2713 No hardcoded paths found{Colors.RESET}\n")
    else:
        # Group findings by file
        by_file: Dict[str, List[Finding]] = {}
        for finding in result.findings:
            if finding.file_path not in by_file:
                by_file[finding.file_path] = []
            by_file[finding.file_path].append(finding)

        # Print each file's findings
        for file_path, findings in sorted(by_file.items()):
            rel_path = os.path.relpath(file_path, directory)
            print(f"\n{Colors.BOLD}{rel_path}{Colors.RESET}")

            for f in sorted(findings, key=lambda x: x.line_number):
                link_text = f"  Line {f.line_number}"
                link = make_hyperlink(f.file_path, f.line_number, link_text)
                # Highlight the matched path within the line content
                highlighted_line = f.line_content.replace(
                    f.matched_path,
                    f"{Colors.RED}{f.matched_path}{Colors.RESET}",
                    1  # Replace only first occurrence
                )
                print(f"{link}: {highlighted_line.strip()}")

    # Summary
    print("\n" + "\u2501" * 50)
    print(f"{Colors.BOLD}Summary:{Colors.RESET}")
    print(f"  Files scanned: {result.files_scanned}")

    if result.findings:
        files_with_issues = len(set(f.file_path for f in result.findings))
        print(f"  Files with issues: {Colors.YELLOW}{files_with_issues}{Colors.RESET}")
        print(f"  Total hardcoded paths: {Colors.RED}{len(result.findings)}{Colors.RESET}")

    # Skip warnings
    if result.files_skipped_encoding > 0:
        print(f"  {Colors.YELLOW}Warning:{Colors.RESET} {result.files_skipped_encoding} files skipped (encoding errors)")
    if result.files_skipped_size > 0:
        print(f"  Skipped {result.files_skipped_size} large files")
    if result.files_skipped_binary > 0:
        print(f"  Skipped {result.files_skipped_binary} binary files")

    print()
