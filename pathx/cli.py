import argparse
import sys
import os

from . import __version__
from .scanner import scan_directory
from .reporter import print_results, print_progress
from .utils import DEFAULT_MAX_FILE_SIZE, DEFAULT_EXCLUDES


def parse_args(args=None):
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog='pathx',
        description='Detect hardcoded filesystem paths in your codebase',
        epilog='Example: pathx ./my-project --exclude vendor'
    )

    parser.add_argument(
        'directory',
        nargs='?',
        default='.',
        help='Directory to scan (default: current directory)'
    )

    parser.add_argument(
        '--exclude', '-e',
        action='append',
        default=[],
        metavar='DIR',
        help='Additional directories to exclude (can be used multiple times)'
    )

    parser.add_argument(
        '--max-size', '-m',
        type=int,
        default=DEFAULT_MAX_FILE_SIZE,
        metavar='BYTES',
        help=f'Skip files larger than this (default: {DEFAULT_MAX_FILE_SIZE // 1024}KB)'
    )

    parser.add_argument(
        '--version', '-v',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser.parse_args(args)


def main(args=None):
    """Main entry point."""
    parsed = parse_args(args)

    # Validate directory
    if not os.path.isdir(parsed.directory):
        print(f"Error: '{parsed.directory}' is not a valid directory", file=sys.stderr)
        sys.exit(2)

    # Merge excludes
    excludes = DEFAULT_EXCLUDES | set(parsed.exclude)

    # Run scan
    result = scan_directory(
        directory=parsed.directory,
        excludes=excludes,
        max_file_size=parsed.max_size,
        progress_callback=print_progress,
    )

    # Print results
    print_results(result, parsed.directory)

    # Exit code: 0 if clean, 1 if issues found
    sys.exit(1 if result.findings else 0)


if __name__ == '__main__':
    main()
