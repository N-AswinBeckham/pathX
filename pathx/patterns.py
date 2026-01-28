import re
from typing import List, Tuple, Pattern

# Pattern tuple: (compiled_regex, category_name, description)
PatternDef = Tuple[Pattern[str], str, str]

# User home paths - highest priority
USER_HOME_PATTERNS: List[PatternDef] = [
    (re.compile(r'["\'](/home/[a-zA-Z0-9_-]+/[^"\']+)["\']'),
     "user_home", "Linux home directory"),
    (re.compile(r'["\'](/Users/[a-zA-Z0-9_-]+/[^"\']+)["\']'),
     "user_home", "macOS home directory"),
    (re.compile(r'["\']([A-Z]:\\Users\\[a-zA-Z0-9_-]+\\[^"\']+)["\']'),
     "user_home", "Windows home directory"),
]

# System paths
SYSTEM_PATTERNS: List[PatternDef] = [
    (re.compile(r'["\'](/usr/local/[^"\']+)["\']'),
     "system", "Unix /usr/local"),
    (re.compile(r'["\'](/opt/[^"\']+)["\']'),
     "system", "Unix /opt"),
    (re.compile(r'["\'](/Applications/[^"\']+)["\']'),
     "system", "macOS Applications"),
    (re.compile(r'["\']([A-Z]:\\Program Files[^"\']*\\[^"\']+)["\']'),
     "system", "Windows Program Files"),
]

# Temp paths
TEMP_PATTERNS: List[PatternDef] = [
    (re.compile(r'["\'](/tmp/[^"\']+)["\']'),
     "temp", "Unix /tmp"),
    (re.compile(r'["\'](/var/tmp/[^"\']+)["\']'),
     "temp", "Unix /var/tmp"),
    (re.compile(r'["\']([A-Z]:\\Temp\\[^"\']+)["\']'),
     "temp", "Windows Temp"),
    (re.compile(r'["\']([A-Z]:\\Windows\\Temp\\[^"\']+)["\']'),
     "temp", "Windows system Temp"),
]

# Combined patterns for scanning
ALL_PATTERNS: List[PatternDef] = (
    USER_HOME_PATTERNS +
    SYSTEM_PATTERNS +
    TEMP_PATTERNS
)


def find_paths_in_line(line: str) -> List[Tuple[str, str, str, int]]:
    """
    Find all hardcoded paths in a line of text.

    Returns: List of (matched_path, category, description, column)
    """
    results = []
    for pattern, category, description in ALL_PATTERNS:
        for match in pattern.finditer(line):
            results.append((
                match.group(1),  # The actual path
                category,
                description,
                match.start(1)   # Column position
            ))
    return results
