import os
from dataclasses import dataclass
from typing import List, Optional, Callable, Set
from enum import Enum

from .patterns import find_paths_in_line, find_relative_paths_in_line, is_creation_context
from .utils import (
    is_binary_file,
    read_file_lines,
    get_file_size,
    should_exclude_dir,
    DEFAULT_EXCLUDES,
    DEFAULT_MAX_FILE_SIZE,
)


class FindingType(Enum):
    """Type of path finding."""
    HARDCODED_ABSOLUTE = "hardcoded_absolute"  # Absolute path that's machine-specific
    MISSING_RELATIVE = "missing_relative"      # Relative path that doesn't exist


@dataclass
class Finding:
    """A single hardcoded path finding."""
    file_path: str
    line_number: int
    column: int
    matched_path: str
    category: str
    line_content: str
    finding_type: FindingType = FindingType.HARDCODED_ABSOLUTE
    description: str = ""


@dataclass
class ScanResult:
    """Complete scan results."""
    findings: List[Finding]
    files_scanned: int
    files_skipped_binary: int
    files_skipped_size: int
    files_skipped_encoding: int
    missing_paths: int = 0  # Count of missing relative paths


def check_path_exists(relative_path: str, source_file: str, scan_root: str) -> bool:
    """
    Check if a relative path exists.

    Checks in order:
    1. Relative to the source file's directory
    2. Relative to the scan root directory

    Args:
        relative_path: The relative path to check
        source_file: The file containing the path reference
        scan_root: The root directory being scanned

    Returns:
        True if the path exists in any of the checked locations
    """
    # Normalize the path (handle ./ and ../)
    if relative_path.startswith('./'):
        relative_path = relative_path[2:]

    # Check relative to source file's directory
    source_dir = os.path.dirname(source_file)
    path_from_source = os.path.normpath(os.path.join(source_dir, relative_path))
    if os.path.exists(path_from_source):
        return True

    # Check relative to scan root
    path_from_root = os.path.normpath(os.path.join(scan_root, relative_path))
    if os.path.exists(path_from_root):
        return True

    return False


def scan_directory(
    directory: str,
    excludes: Optional[Set[str]] = None,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    progress_callback: Optional[Callable[[int, str], None]] = None,
    check_relative_paths: bool = True,
) -> ScanResult:
    """
    Scan a directory for hardcoded paths and missing relative paths.

    Args:
        directory: Path to scan
        excludes: Directory names to exclude
        max_file_size: Skip files larger than this (bytes)
        progress_callback: Called with (file_count, current_file)
        check_relative_paths: Whether to verify relative paths exist

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
    missing_paths_count = 0

    # Get absolute path for scan root
    scan_root = os.path.abspath(directory)

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
                # Check for hardcoded absolute paths
                for matched_path, category, desc, column in find_paths_in_line(line):
                    findings.append(Finding(
                        file_path=file_path,
                        line_number=line_num,
                        column=column,
                        matched_path=matched_path,
                        category=category,
                        line_content=line.rstrip('\n\r'),
                        finding_type=FindingType.HARDCODED_ABSOLUTE,
                        description=desc,
                    ))

                # Check for missing relative paths
                if check_relative_paths:
                    for matched_path, category, desc, column in find_relative_paths_in_line(line):
                        # Skip if this is a creation context (file will be created)
                        if is_creation_context(line, column):
                            continue

                        # Check if the path exists
                        if not check_path_exists(matched_path, file_path, scan_root):
                            findings.append(Finding(
                                file_path=file_path,
                                line_number=line_num,
                                column=column,
                                matched_path=matched_path,
                                category="missing_path",
                                line_content=line.rstrip('\n\r'),
                                finding_type=FindingType.MISSING_RELATIVE,
                                description=f"File/directory not found: {matched_path}",
                            ))
                            missing_paths_count += 1

    return ScanResult(
        findings=findings,
        files_scanned=files_scanned,
        files_skipped_binary=files_skipped_binary,
        files_skipped_size=files_skipped_size,
        files_skipped_encoding=files_skipped_encoding,
        missing_paths=missing_paths_count,
    )
