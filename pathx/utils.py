import os
from typing import Optional, Set, List

# Default directories to exclude
DEFAULT_EXCLUDES: Set[str] = {
    '.git',
    'node_modules',
    '__pycache__',
    'venv',
    '.venv',
    'build',
    'dist',
    '.tox',
    'eggs',
    '.egg-info',
}

# Default max file size (1MB)
DEFAULT_MAX_FILE_SIZE: int = 1024 * 1024


def is_binary_file(file_path: str, sample_size: int = 8192) -> bool:
    """
    Check if a file is binary by looking for null bytes.
    """
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(sample_size)
            return b'\x00' in chunk
    except (IOError, OSError):
        return True  # Treat unreadable as binary


def read_file_lines(file_path: str) -> Optional[List[str]]:
    """
    Read a file and return its lines.
    Returns None if file cannot be read (encoding error, etc.)
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.readlines()
    except UnicodeDecodeError:
        return None
    except (IOError, OSError):
        return None


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    try:
        return os.path.getsize(file_path)
    except OSError:
        return 0


def should_exclude_dir(dir_name: str, excludes: Set[str]) -> bool:
    """Check if a directory should be excluded."""
    return dir_name in excludes or dir_name.startswith('.')
