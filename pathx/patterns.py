"""
Comprehensive pattern definitions for detecting hardcoded absolute paths.

This module provides extensive regex patterns to detect hardcoded paths across:
- Multiple operating systems (Linux, macOS, Windows)
- Various string formats (quoted, backtick, raw, unquoted in configs)
- Different path categories (user home, system, config, temp, network, etc.)
- Special cases (shebang, file URLs, environment variables, WSL, UNC)
"""

import re
from typing import List, Tuple, Pattern, Optional
from dataclasses import dataclass
from enum import Enum


class Severity(Enum):
    """Severity levels for detected paths."""
    CRITICAL = "critical"   # User-specific paths that will break on other machines
    HIGH = "high"           # System paths that may vary between installations
    MEDIUM = "medium"       # Temp/cache paths that may cause issues
    LOW = "low"             # Informational - might be intentional
    INFO = "info"           # Environment variable references (may be OK)


@dataclass
class PatternDefinition:
    """Definition for a path detection pattern."""
    pattern: Pattern[str]
    category: str
    description: str
    severity: Severity
    group_index: int = 1  # Which capture group contains the path

    def __iter__(self):
        """Allow tuple unpacking for backwards compatibility."""
        return iter((self.pattern, self.category, self.description))


# Pattern tuple: (compiled_regex, category_name, description) for backwards compatibility
PatternDef = Tuple[Pattern[str], str, str]


# =============================================================================
# HELPER FUNCTIONS FOR PATTERN BUILDING
# =============================================================================

def _quoted_pattern(path_regex: str) -> str:
    """Wrap a path pattern to match inside single or double quotes."""
    return rf'''["']({path_regex})["']'''


def _backtick_pattern(path_regex: str) -> str:
    """Wrap a path pattern to match inside backticks."""
    return rf'`({path_regex})`'


def _any_string_pattern(path_regex: str) -> str:
    """Match path in quotes, backticks, or raw string prefixes."""
    return rf'''(?:["'`]|[rRbBuU]["'`]|[rRbBfF][rRbBfF]?["'`])({path_regex})["'`]'''


# Username pattern component - matches typical usernames
USERNAME = r'[a-zA-Z0-9_][a-zA-Z0-9_.-]*'

# Path continuation after root - excludes quote chars and common delimiters
PATH_CHARS = r'''[^"'`\s\n\r<>|*?]+'''
PATH_CHARS_QUOTED = r'''[^"'`]+'''


# =============================================================================
# USER HOME PATHS - CRITICAL SEVERITY
# These paths are machine-specific and will almost certainly break elsewhere
# =============================================================================

USER_HOME_PATTERNS: List[PatternDefinition] = [
    # Linux home directories
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/{PATH_CHARS_QUOTED})["'`]''', re.IGNORECASE),
        "user_home", "Linux home directory path", Severity.CRITICAL
    ),
    # Unquoted Linux home (config files, shebangs, etc.)
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/home/{USERNAME}/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "user_home", "Linux home directory (unquoted)", Severity.CRITICAL
    ),

    # macOS home directories
    PatternDefinition(
        re.compile(rf'''["'`](/Users/{USERNAME}/{PATH_CHARS_QUOTED})["'`]''', re.IGNORECASE),
        "user_home", "macOS home directory path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/Users/{USERNAME}/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "user_home", "macOS home directory (unquoted)", Severity.CRITICAL
    ),

    # Windows home directories (various drive letters)
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Users\\{USERNAME}\\{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Windows home directory path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:/Users/{USERNAME}/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Windows home directory (forward slash)", Severity.CRITICAL
    ),

    # Root home directory (Unix)
    PatternDefinition(
        re.compile(rf'''["'`](/root/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Root home directory", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/root/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "user_home", "Root home directory (unquoted)", Severity.CRITICAL
    ),

    # Tilde expansion in strings (usually a mistake when hardcoded)
    PatternDefinition(
        re.compile(rf'''["'`](~/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Tilde home path (may not expand)", Severity.HIGH
    ),

    # macOS User Library
    PatternDefinition(
        re.compile(rf'''["'`](/Users/{USERNAME}/Library/{PATH_CHARS_QUOTED})["'`]''', re.IGNORECASE),
        "user_home", "macOS user Library path", Severity.CRITICAL
    ),

    # Windows AppData paths
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Users\\{USERNAME}\\AppData\\{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Windows AppData path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:/Users/{USERNAME}/AppData/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "Windows AppData path (forward slash)", Severity.CRITICAL
    ),

    # XDG directories that resolve to home
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.config/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "XDG config directory", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.local/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "XDG local directory", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.cache/{PATH_CHARS_QUOTED})["'`]'''),
        "user_home", "XDG cache directory", Severity.CRITICAL
    ),
]


# =============================================================================
# SYSTEM PATHS - HIGH SEVERITY
# These may work across machines but indicate hardcoded system dependencies
# =============================================================================

SYSTEM_PATTERNS: List[PatternDefinition] = [
    # Unix /usr paths
    PatternDefinition(
        re.compile(rf'''["'`](/usr/local/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Unix /usr/local path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/usr/local/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "system", "Unix /usr/local path (unquoted)", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/usr/share/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Unix /usr/share path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/usr/lib/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Unix /usr/lib path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/usr/bin/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Unix /usr/bin path", Severity.MEDIUM
    ),

    # /opt directory (third-party software)
    PatternDefinition(
        re.compile(rf'''["'`](/opt/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Unix /opt path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/opt/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "system", "Unix /opt path (unquoted)", Severity.HIGH
    ),

    # macOS specific system paths
    PatternDefinition(
        re.compile(rf'''["'`](/Applications/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "macOS Applications path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/Library/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "macOS system Library path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/System/Library/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "macOS System Library path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/Volumes/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "macOS Volumes path", Severity.HIGH
    ),

    # Windows Program Files
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Program Files\\{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Windows Program Files path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Program Files \(x86\)\\{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Windows Program Files (x86) path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:/Program Files/{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Windows Program Files (forward slash)", Severity.HIGH
    ),

    # Windows system directories
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Windows\\{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Windows system directory", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\ProgramData\\{PATH_CHARS_QUOTED})["'`]'''),
        "system", "Windows ProgramData path", Severity.HIGH
    ),
]


# =============================================================================
# CONFIGURATION PATHS - MEDIUM TO HIGH SEVERITY
# System configuration that varies between installations
# =============================================================================

CONFIG_PATTERNS: List[PatternDefinition] = [
    # Unix /etc
    PatternDefinition(
        re.compile(rf'''["'`](/etc/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /etc configuration path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/etc/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "config", "Unix /etc configuration path (unquoted)", Severity.HIGH
    ),

    # /var/lib - application state
    PatternDefinition(
        re.compile(rf'''["'`](/var/lib/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /var/lib application data", Severity.MEDIUM
    ),

    # /var/log - log files
    PatternDefinition(
        re.compile(rf'''["'`](/var/log/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /var/log path", Severity.MEDIUM
    ),

    # /var/run and /run - runtime data
    PatternDefinition(
        re.compile(rf'''["'`](/var/run/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /var/run runtime path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/run/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /run runtime path", Severity.MEDIUM
    ),

    # /srv - service data
    PatternDefinition(
        re.compile(rf'''["'`](/srv/{PATH_CHARS_QUOTED})["'`]'''),
        "config", "Unix /srv service data", Severity.MEDIUM
    ),
]


# =============================================================================
# TEMPORARY PATHS - MEDIUM SEVERITY
# May cause issues with cleanup, permissions, or path expectations
# =============================================================================

TEMP_PATTERNS: List[PatternDefinition] = [
    # Unix temp directories
    PatternDefinition(
        re.compile(rf'''["'`](/tmp/{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "Unix /tmp path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/tmp/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "temp", "Unix /tmp path (unquoted)", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/var/tmp/{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "Unix /var/tmp path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/private/tmp/{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "macOS /private/tmp path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/private/var/{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "macOS /private/var path", Severity.MEDIUM
    ),

    # Windows temp directories
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Temp\\{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "Windows Temp path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Windows\\Temp\\{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "Windows system Temp path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\Users\\{USERNAME}\\AppData\\Local\\Temp\\{PATH_CHARS_QUOTED})["'`]'''),
        "temp", "Windows user Temp path", Severity.MEDIUM
    ),
]


# =============================================================================
# MOUNT AND MEDIA PATHS - HIGH SEVERITY
# External mounts that are machine-specific
# =============================================================================

MOUNT_PATTERNS: List[PatternDefinition] = [
    # Unix mount points
    PatternDefinition(
        re.compile(rf'''["'`](/mnt/{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "Unix /mnt mount path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/mnt/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "mount", "Unix /mnt mount path (unquoted)", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/media/{USERNAME}/{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "Unix /media user mount", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/media/{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "Unix /media mount path", Severity.HIGH
    ),

    # WSL mount paths (Windows drives mounted in WSL)
    PatternDefinition(
        re.compile(rf'''["'`](/mnt/[a-z]/{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "WSL Windows drive mount", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''(?:^|[\s=:])(/mnt/[a-z]/{PATH_CHARS})(?:$|[\s:,;\]\}}\)])'''),
        "mount", "WSL Windows drive mount (unquoted)", Severity.HIGH
    ),

    # Non-C drive letters (Windows)
    PatternDefinition(
        re.compile(rf'''["'`]([D-Zd-z]:\\{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "Windows non-system drive path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([D-Zd-z]:/{PATH_CHARS_QUOTED})["'`]'''),
        "mount", "Windows non-system drive (forward slash)", Severity.HIGH
    ),
]


# =============================================================================
# NETWORK AND UNC PATHS - HIGH SEVERITY
# Network shares that are environment-specific
# =============================================================================

NETWORK_PATTERNS: List[PatternDefinition] = [
    # Windows UNC paths
    PatternDefinition(
        re.compile(rf'''["'`](\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$-]+\\{PATH_CHARS_QUOTED})["'`]'''),
        "network", "Windows UNC network path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`](\\\\[a-zA-Z0-9_.-]+\\[a-zA-Z0-9_.$-]+)["'`]'''),
        "network", "Windows UNC share root", Severity.HIGH
    ),

    # Unix-style SMB paths
    PatternDefinition(
        re.compile(rf'''["'`](//[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+/{PATH_CHARS_QUOTED})["'`]'''),
        "network", "Unix SMB network path", Severity.HIGH
    ),

    # NFS-style paths with server prefix
    # Exclude common URL schemes (http, https, ftp, ssh, git, file, etc.)
    PatternDefinition(
        re.compile(rf'''["'`](?!(?:https?|ftp|ssh|git|file|mailto|tel|data|s3|gs):)([a-zA-Z0-9_-][a-zA-Z0-9_.-]*:/{PATH_CHARS_QUOTED})["'`]'''),
        "network", "NFS-style remote path", Severity.HIGH
    ),
]


# =============================================================================
# SPECIAL FORMAT PATHS
# Shebang, file URLs, environment variables, etc.
# =============================================================================

SPECIAL_PATTERNS: List[PatternDefinition] = [
    # Shebang with absolute path
    PatternDefinition(
        re.compile(rf'''^#!(/home/{USERNAME}/{PATH_CHARS})'''),
        "shebang", "Shebang with user home path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''^#!(/Users/{USERNAME}/{PATH_CHARS})'''),
        "shebang", "Shebang with macOS home path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''^#!(/usr/local/{PATH_CHARS})'''),
        "shebang", "Shebang with /usr/local path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''^#!(/opt/{PATH_CHARS})'''),
        "shebang", "Shebang with /opt path", Severity.HIGH
    ),

    # File URLs
    PatternDefinition(
        re.compile(rf'''["'`]?(file:///home/{USERNAME}/{PATH_CHARS_QUOTED}?)["'`]?'''),
        "file_url", "File URL with home path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(file:///Users/{USERNAME}/{PATH_CHARS_QUOTED}?)["'`]?'''),
        "file_url", "File URL with macOS home path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(file:///[A-Za-z]:/{PATH_CHARS_QUOTED}?)["'`]?'''),
        "file_url", "File URL with Windows path", Severity.HIGH
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(file:///{PATH_CHARS_QUOTED})["'`]?'''),
        "file_url", "File URL with absolute path", Severity.MEDIUM
    ),

    # Windows environment variable references (may indicate path building)
    PatternDefinition(
        re.compile(rf'''["'`]?(%USERPROFILE%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %USERPROFILE% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%APPDATA%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %APPDATA% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%LOCALAPPDATA%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %LOCALAPPDATA% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%PROGRAMFILES%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %PROGRAMFILES% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%TEMP%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %TEMP% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%TMP%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %TMP% reference", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]?(%HOMEDRIVE%%HOMEPATH%\\{PATH_CHARS_QUOTED}?)["'`]?'''),
        "env_ref", "Windows %HOMEDRIVE%%HOMEPATH% reference", Severity.INFO
    ),

    # Path with embedded variables (Unix style)
    PatternDefinition(
        re.compile(rf'''["'`](/home/\$\{{?USER\}}?/{PATH_CHARS_QUOTED})["'`]'''),
        "env_ref", "Path with $USER variable", Severity.LOW
    ),
    PatternDefinition(
        re.compile(rf'''["'`](\$HOME/{PATH_CHARS_QUOTED})["'`]'''),
        "env_ref", "Path with $HOME variable", Severity.LOW
    ),
]


# =============================================================================
# BUILD TOOL AND IDE PATHS
# Common development tool cache/config locations
# =============================================================================

BUILD_PATTERNS: List[PatternDefinition] = [
    # Gradle cache
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.gradle/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Gradle cache path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/Users/{USERNAME}/\.gradle/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Gradle cache path (macOS)", Severity.CRITICAL
    ),

    # Maven cache
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.m2/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Maven cache path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/Users/{USERNAME}/\.m2/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Maven cache path (macOS)", Severity.CRITICAL
    ),

    # npm/node cache
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.npm/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "npm cache path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.nvm/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "nvm path", Severity.CRITICAL
    ),

    # Cargo/Rust cache
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.cargo/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Cargo cache path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.rustup/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Rustup path", Severity.CRITICAL
    ),

    # Python virtual environments with absolute paths
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/{PATH_CHARS_QUOTED}?venv/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Python venv path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/{PATH_CHARS_QUOTED}?\.venv/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Python .venv path", Severity.CRITICAL
    ),

    # Go paths
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/go/{PATH_CHARS_QUOTED})["'`]'''),
        "build_cache", "Go workspace path", Severity.CRITICAL
    ),

    # IDE settings
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.vscode/{PATH_CHARS_QUOTED})["'`]'''),
        "ide_config", "VS Code settings path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.config/Code/{PATH_CHARS_QUOTED})["'`]'''),
        "ide_config", "VS Code config path", Severity.CRITICAL
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/home/{USERNAME}/\.idea/{PATH_CHARS_QUOTED})["'`]'''),
        "ide_config", "IntelliJ settings path", Severity.CRITICAL
    ),
]


# =============================================================================
# CONTAINER AND CLOUD PATHS
# Docker, Kubernetes, cloud storage mounts
# =============================================================================

CONTAINER_PATTERNS: List[PatternDefinition] = [
    # Common Docker volume mount patterns that expose host paths
    PatternDefinition(
        re.compile(rf'''["'`](/var/lib/docker/{PATH_CHARS_QUOTED})["'`]'''),
        "container", "Docker lib path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/var/run/docker\.sock)["'`]'''),
        "container", "Docker socket path", Severity.HIGH
    ),

    # Kubernetes paths
    PatternDefinition(
        re.compile(rf'''["'`](/var/lib/kubelet/{PATH_CHARS_QUOTED})["'`]'''),
        "container", "Kubelet data path", Severity.MEDIUM
    ),
    PatternDefinition(
        re.compile(rf'''["'`](/etc/kubernetes/{PATH_CHARS_QUOTED})["'`]'''),
        "container", "Kubernetes config path", Severity.HIGH
    ),
]


# =============================================================================
# RELATIVE PATH PATTERNS - For existence verification
# These detect relative paths that may break if files don't exist
# =============================================================================

# Patterns for common file access operations (read/load context)
ACCESS_FUNCTIONS = r'''(?:
    open\s*\(|
    read|load|parse|
    json\.load|yaml\.safe_load|yaml\.load|
    pd\.read_|pandas\.read_|
    np\.load|numpy\.load|
    torch\.load|
    cv2\.imread|cv\.imread|
    Image\.open|PIL\.Image\.open|
    Path\(|pathlib\.Path\(|
    os\.path\.exists|os\.path\.isfile|os\.path\.isdir|
    os\.listdir|os\.scandir|
    glob\.glob|
    shutil\.copy|shutil\.move|
    include|require|import|from\s+
)'''

# Patterns for file/directory creation (we'll exclude these from missing-file warnings)
CREATION_PATTERNS_STR = r'''(?:
    open\s*\([^)]*['\"][wax]['\"]|
    open\s*\([^)]*mode\s*=\s*['\"][wax]|
    \.write\(|\.writelines\(|
    os\.makedirs?|os\.mkdir|
    Path\([^)]*\)\.mkdir|
    \.touch\(|
    shutil\.copytree|
    with\s+open\s*\([^)]*['\"][wax]
)'''

# Relative path patterns
RELATIVE_PATH_CHARS = r'''[a-zA-Z0-9_][a-zA-Z0-9_./-]*'''

RELATIVE_PATTERNS: List[PatternDefinition] = [
    # Explicit ./path patterns
    PatternDefinition(
        re.compile(rf'''["'`](\./[a-zA-Z0-9_][a-zA-Z0-9_./-]*)["'`]'''),
        "relative_path", "Relative path with ./ prefix", Severity.INFO
    ),
    # Explicit ../path patterns (parent directory)
    PatternDefinition(
        re.compile(rf'''["'`](\.\.(?:/\.\.)*/?[a-zA-Z0-9_][a-zA-Z0-9_./-]*)["'`]'''),
        "relative_path", "Relative path with ../ prefix", Severity.INFO
    ),
    # Implicit relative paths (no ./ prefix) - common patterns
    # Config files
    PatternDefinition(
        re.compile(rf'''["'`](config/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative config path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](configs/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative configs path", Severity.INFO
    ),
    # Data directories
    PatternDefinition(
        re.compile(rf'''["'`](data/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative data path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](datasets?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative dataset path", Severity.INFO
    ),
    # Model/weights directories
    PatternDefinition(
        re.compile(rf'''["'`](models?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative model path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](weights?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative weights path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](checkpoints?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative checkpoint path", Severity.INFO
    ),
    # Output/results directories
    PatternDefinition(
        re.compile(rf'''["'`](output/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative output path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](outputs?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative outputs path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](results?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative results path", Severity.INFO
    ),
    # Assets/resources
    PatternDefinition(
        re.compile(rf'''["'`](assets?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative assets path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](resources?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative resources path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](static/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative static path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](templates?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative templates path", Severity.INFO
    ),
    # Source directories
    PatternDefinition(
        re.compile(rf'''["'`](src/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative src path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](lib/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative lib path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](scripts?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative scripts path", Severity.INFO
    ),
    # Logs
    PatternDefinition(
        re.compile(rf'''["'`](logs?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative logs path", Severity.INFO
    ),
    # Cache/temp
    PatternDefinition(
        re.compile(rf'''["'`](cache/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative cache path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](tmp/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative tmp path", Severity.INFO
    ),
    # Test fixtures
    PatternDefinition(
        re.compile(rf'''["'`](tests?/[a-zA-Z0-9_./-]+\.(json|yaml|yml|txt|csv|xml))["'`]'''),
        "relative_path", "Relative test fixture path", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`](fixtures?/[a-zA-Z0-9_./-]+)["'`]'''),
        "relative_path", "Relative fixtures path", Severity.INFO
    ),
    # Specific file types that are commonly loaded
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:json|yaml|yml|toml|ini|cfg|conf))["'`]'''),
        "relative_path", "Relative config file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:csv|tsv|parquet|pkl|pickle|npy|npz))["'`]'''),
        "relative_path", "Relative data file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:pt|pth|ckpt|h5|hdf5|pb|onnx|safetensors))["'`]'''),
        "relative_path", "Relative model file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:png|jpg|jpeg|gif|bmp|svg|ico|webp))["'`]'''),
        "relative_path", "Relative image file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:mp4|avi|mov|mkv|webm|mp3|wav|flac))["'`]'''),
        "relative_path", "Relative media file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:txt|md|rst|log))["'`]'''),
        "relative_path", "Relative text file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:sql|db|sqlite|sqlite3))["'`]'''),
        "relative_path", "Relative database file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:xml|html|htm|xhtml))["'`]'''),
        "relative_path", "Relative markup file", Severity.INFO
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([a-zA-Z0-9_][a-zA-Z0-9_./-]*\.(?:sh|bash|zsh|ps1|bat|cmd))["'`]'''),
        "relative_path", "Relative script file", Severity.INFO
    ),
]


# =============================================================================
# GENERIC ABSOLUTE PATHS (catch-all, lower priority)
# =============================================================================

GENERIC_PATTERNS: List[PatternDefinition] = [
    # Any quoted Unix absolute path not caught by specific patterns
    # This is a catch-all with lower priority
    PatternDefinition(
        re.compile(rf'''["'`](\/[a-zA-Z][a-zA-Z0-9_.-]*(?:\/[a-zA-Z0-9_.-]+)+)["'`]'''),
        "absolute_path", "Generic Unix absolute path", Severity.LOW
    ),

    # Any quoted Windows absolute path not caught by specific patterns
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:\\[a-zA-Z0-9_.-]+(?:\\[a-zA-Z0-9_. -]+)+)["'`]'''),
        "absolute_path", "Generic Windows absolute path", Severity.LOW
    ),
    PatternDefinition(
        re.compile(rf'''["'`]([A-Za-z]:/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_. -]+)+)["'`]'''),
        "absolute_path", "Generic Windows path (forward slash)", Severity.LOW
    ),
]


# =============================================================================
# COMBINED PATTERNS - ORDERED BY PRIORITY
# More specific patterns come before general patterns to ensure correct matching
# =============================================================================

ALL_PATTERN_DEFINITIONS: List[PatternDefinition] = (
    USER_HOME_PATTERNS +
    BUILD_PATTERNS +        # Build cache includes user paths, check early
    SPECIAL_PATTERNS +      # Shebangs and file URLs
    CONTAINER_PATTERNS +    # Container paths before config (docker.sock vs /var/run)
    SYSTEM_PATTERNS +
    CONFIG_PATTERNS +
    NETWORK_PATTERNS +
    MOUNT_PATTERNS +
    TEMP_PATTERNS +
    GENERIC_PATTERNS        # Catch-all last
)

# Relative patterns kept separate for existence verification
ALL_RELATIVE_PATTERNS: List[PatternDefinition] = RELATIVE_PATTERNS

# Backwards-compatible tuple format
ALL_PATTERNS: List[PatternDef] = [
    (p.pattern, p.category, p.description) for p in ALL_PATTERN_DEFINITIONS
]


def get_severity(category: str) -> Severity:
    """Get severity level for a category."""
    severity_map = {
        "user_home": Severity.CRITICAL,
        "build_cache": Severity.CRITICAL,
        "ide_config": Severity.CRITICAL,
        "shebang": Severity.CRITICAL,
        "file_url": Severity.HIGH,
        "system": Severity.HIGH,
        "config": Severity.HIGH,
        "network": Severity.HIGH,
        "mount": Severity.HIGH,
        "container": Severity.MEDIUM,
        "temp": Severity.MEDIUM,
        "env_ref": Severity.INFO,
        "absolute_path": Severity.LOW,
    }
    return severity_map.get(category, Severity.MEDIUM)


def find_paths_in_line(line: str) -> List[Tuple[str, str, str, int]]:
    """
    Find all hardcoded paths in a line of text.

    This function scans a line of text for hardcoded absolute paths using
    an extensive set of patterns covering multiple operating systems,
    string formats, and path categories.

    Args:
        line: A single line of text to scan

    Returns:
        List of tuples: (matched_path, category, description, column)
        - matched_path: The actual path string that was found
        - category: Category of the path (user_home, system, temp, etc.)
        - description: Human-readable description of what was found
        - column: 0-based column position where the path starts
    """
    if not line or not line.strip():
        return []

    results = []
    seen_paths = set()  # Avoid duplicate matches from overlapping patterns

    for pattern_def in ALL_PATTERN_DEFINITIONS:
        pattern = pattern_def.pattern
        category = pattern_def.category
        description = pattern_def.description
        group_index = pattern_def.group_index

        for match in pattern.finditer(line):
            try:
                path = match.group(group_index)
                if path and path not in seen_paths:
                    # Skip if this looks like a URL (http://, https://, etc.)
                    # Check the context before the match
                    start = match.start(group_index)
                    prefix = line[max(0, start-10):start].lower()
                    if any(proto in prefix for proto in ['http://', 'https://', 'ftp://', 'ssh://', 'git://']):
                        continue

                    seen_paths.add(path)
                    results.append((
                        path,
                        category,
                        description,
                        match.start(group_index)
                    ))
            except IndexError:
                # Group doesn't exist in this match
                continue

    # Sort by column position for consistent ordering
    results.sort(key=lambda x: x[3])

    return results


def find_paths_in_line_with_severity(line: str) -> List[Tuple[str, str, str, int, Severity]]:
    """
    Find all hardcoded paths in a line with severity information.

    Args:
        line: A single line of text to scan

    Returns:
        List of tuples: (matched_path, category, description, column, severity)
    """
    basic_results = find_paths_in_line(line)
    return [
        (path, cat, desc, col, get_severity(cat))
        for path, cat, desc, col in basic_results
    ]


def is_creation_context(line: str, path_column: int) -> bool:
    """
    Check if the path appears in a file/directory creation context.

    This helps distinguish between:
    - Access: open(path, 'r'), load(path), pd.read_csv(path)
    - Creation: open(path, 'w'), makedirs(path), touch(path)

    Args:
        line: The full line of code
        path_column: Column position where the path starts

    Returns:
        True if this looks like a creation context (shouldn't warn about missing)
    """
    line_lower = line.lower()
    # Get context before the path
    prefix = line[:path_column].lower()
    # Get context after the path (for open() mode detection)
    suffix = line[path_column:].lower()

    # Check for write mode in open() calls
    # Pattern: open(path, 'w') where mode comes AFTER the path
    if 'open(' in prefix:
        # Look for write modes in the suffix (after the path)
        write_modes = ["'w'", '"w"', "'a'", '"a"', "'x'", '"x"',
                       "'wb'", '"wb"', "'ab'", '"ab"', "'xb'", '"xb"',
                       "mode='w", 'mode="w', "mode='a", 'mode="a',
                       ", 'w'", ', "w"', ", 'a'", ', "a"', ", 'x'", ', "x"']
        if any(m in suffix for m in write_modes):
            return True
        # Also check prefix for cases like: open(mode='w', file=path)
        if any(m in prefix for m in write_modes):
            return True

    # Check for directory/file creation functions
    creation_funcs = [
        'makedirs(', 'mkdir(', 'makedirs (',  'mkdir (',
        '.mkdir(', '.touch(', 'touch(',
        'create(', 'write(', 'writelines(',
        'dump(', 'save(', 'to_csv(', 'to_json(', 'to_pickle(',
        'savefig(', 'imsave(', 'imwrite(',
        'torch.save(', 'np.save(', 'pickle.dump(',
        'shutil.copytree(',
    ]

    if any(func in prefix for func in creation_funcs):
        return True

    # Check for assignment to output variable names
    output_vars = ['output', 'out_', 'save_', 'dest', 'target', 'dst']
    if any(var in prefix for var in output_vars):
        # Only if it looks like assignment: output_path = "..."
        if '=' in prefix:
            return True

    return False


def find_relative_paths_in_line(line: str) -> List[Tuple[str, str, str, int]]:
    """
    Find all relative paths in a line of text.

    Args:
        line: A single line of text to scan

    Returns:
        List of tuples: (matched_path, category, description, column)
    """
    if not line or not line.strip():
        return []

    results = []
    seen_paths = set()

    for pattern_def in ALL_RELATIVE_PATTERNS:
        pattern = pattern_def.pattern
        category = pattern_def.category
        description = pattern_def.description
        group_index = pattern_def.group_index

        for match in pattern.finditer(line):
            try:
                path = match.group(group_index)
                if path and path not in seen_paths:
                    # Skip common false positives
                    # Skip if it looks like a URL
                    if path.startswith(('http://', 'https://', 'ftp://', 'file://')):
                        continue
                    # Skip version strings like "1.0.0"
                    if re.match(r'^\d+\.\d+', path):
                        continue
                    # Skip module imports (single word without extension or with .py)
                    if '/' not in path and '\\' not in path:
                        # Skip if it's a simple module name without file extension
                        # Allow config files like settings.json
                        if '.' not in path or path.endswith('.py'):
                            continue

                    seen_paths.add(path)
                    results.append((
                        path,
                        category,
                        description,
                        match.start(group_index)
                    ))
            except IndexError:
                continue

    # Sort by column position
    results.sort(key=lambda x: x[3])
    return results


def get_pattern_stats() -> dict:
    """Get statistics about the pattern definitions."""
    categories = {}
    for p in ALL_PATTERN_DEFINITIONS:
        if p.category not in categories:
            categories[p.category] = {"count": 0, "severity": p.severity.value}
        categories[p.category]["count"] += 1

    return {
        "total_patterns": len(ALL_PATTERN_DEFINITIONS),
        "categories": categories,
        "severity_counts": {
            s.value: sum(1 for p in ALL_PATTERN_DEFINITIONS if p.severity == s)
            for s in Severity
        }
    }
