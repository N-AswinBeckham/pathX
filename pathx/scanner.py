import os
from dataclasses import dataclass
from typing import List, Optional, Callable, Set

from .patterns import find_paths_in_line
from .utils import (
    is_binary_file,
    read_file_lines,
    get_file_size,
    should_exclude_dir,
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_FILE_SIZE,
)


@dataclass
class Finding:
    """A single hardcoded path finding."""
    file_path: str
    line_number: int
    column: int
    matched_path: str
    category: str
    line_content: str


@dataclass
class ScanResult:
    """Complete scan results."""
    findings: List[Finding]
    files_scanned: int
    files_skipped_binary: int
    files_skipped_size: int
    files_skipped_encoding: int


def scan_directory(
    directory: str,
    excludes: Optional[Set[str]] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> ScanResult:
    """
    Scan a directory for hardcoded paths.

    Args:
        directory: Path to scan
        excludes: Directory names to exclude
        max_file_size: Skip files larger than this (bytes)
        progress_callback: Called with (file_count, current_file)

    Returns:
        ScanResult with all findings and statistics
    """
    if excludes is None:
        excludes = DEFAULT_EXCLUDES

    findings: List[Finding] = []
    files_scanned = 0
    files_skipped_binary = 0
    files_skipped_size = 0
    files_skipped_encoding = 0

    for root, dirs, files in os.walk(directory):
        # Filter out excluded directories (modifies in-place)
        dirs[:] = [d for d in dirs if not should_exclude_dir(d, excludes)]

        for filename in files:
            file_path = os.path.join(root, filename)

            # Check file size
            if get_file_size(file_path) > max_file_size:
                files_skipped_size += 1
                continue

            # Check if binary
            if is_binary_file(file_path):
                files_skipped_binary += 1
                continue

            # Progress callback
            if progress_callback:
                progress_callback(files_scanned, file_path)

            # Read and scan file
            lines = read_file_lines(file_path)
            if lines is None:
                files_skipped_encoding += 1
                continue

            files_scanned += 1

            for line_num, line in enumerate(lines, start=1):
                for matched_path, category, _, column in find_paths_in_line(line):
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        column=column,
                        matched_path=matched_path,
                        category=category,
                        line_content=line.rstrip('\n\r'),
                    ))

    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_skipped_binary=files_skipped_binary,
        files_skipped_size=files_skipped_size,
        files_skipped_encoding=files_skipped_encoding,
    )
