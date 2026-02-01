# PathX

A smart CLI tool that detects hardcoded filesystem paths and missing relative files in your codebase. Built for developers who want to catch path-related bugs before they cause runtime failures.

## Why PathX?

Hardcoded paths are a common source of bugs:
- Code works on your machine but breaks when cloned by teammates
- `/home/john/project/config.json` doesn't exist on Jane's computer
- That `data/model.pth` file is missing after a fresh clone
- Paths that worked in development fail in production

PathX helps you catch these issues early by scanning your code for:
1. **Hardcoded absolute paths** - Paths like `/home/user/...` or `C:\Users\...` that won't work on other machines
2. **Missing relative files** - References to `config/settings.json` or `data/train.csv` that don't actually exist

## Installation

```bash
pip install pathx
```

Or install from source:
```bash
git clone https://github.com/your-repo/pathX.git
cd pathX
pip install -e .
```

## Quick Start

```bash
# Scan current directory
pathx

# Scan a specific project
pathx /path/to/your/project

# Scan but ignore missing file checks
pathx --no-missing-check
```

## What PathX Detects

### Hardcoded Absolute Paths

PathX detects machine-specific paths across all major operating systems:

| Category | Examples |
|----------|----------|
| **User Home** | `/home/user/...`, `/Users/john/...`, `C:\Users\dev\...` |
| **System Paths** | `/usr/local/...`, `/opt/...`, `C:\Program Files\...` |
| **Config Paths** | `/etc/...`, `/var/lib/...` |
| **Temp Paths** | `/tmp/...`, `C:\Temp\...` |
| **Mount Points** | `/mnt/...`, `/media/...`, `/Volumes/...` |
| **Network Shares** | `\\server\share\...`, `//server/share/...` |
| **Build Caches** | `~/.gradle/...`, `~/.m2/...`, `~/.npm/...` |

### Missing Relative Paths

PathX verifies that referenced files actually exist:

```python
# PathX will warn if config/settings.json doesn't exist
config = json.load(open("config/settings.json"))

# PathX will warn if models/checkpoint.pth doesn't exist
model = torch.load("models/checkpoint.pth")

# PathX will NOT warn - this is a creation context (writing, not reading)
df.to_csv("output/results.csv")
```

**Smart Context Detection**: PathX distinguishes between file access (reading/loading) and file creation (writing/saving). It only warns about missing files when you're trying to *read* them, not when you're *creating* them.

Detected file types include:
- Config files: `.json`, `.yaml`, `.yml`, `.toml`, `.ini`, `.cfg`
- Data files: `.csv`, `.parquet`, `.pkl`, `.npy`, `.npz`
- Model files: `.pth`, `.ckpt`, `.h5`, `.onnx`, `.safetensors`
- Images: `.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`
- Databases: `.db`, `.sqlite`, `.sqlite3`
- And many more...

## Example Output

```
PathX - Hardcoded Path Detector
Scanned: /Users/dev/my-project
--------------------------------------------------

Hardcoded Absolute Paths:
----------------------------------------

src/config.py
  Line 5: DATABASE = "/home/developer/data/db.sqlite"

scripts/deploy.sh
  Line 12: INSTALL_DIR="/opt/myapp"

Missing Relative Paths:
----------------------------------------

train.py
  Line 8: config = load("config/experiment.yaml")
       ^ File not found
  Line 15: model = torch.load("weights/pretrained.pth")
       ^ File not found

--------------------------------------------------
Summary:
  Files scanned: 42
  Files with issues: 3
  Hardcoded paths: 2
  Missing relative paths: 2
```

## Command Line Options

```
Usage: pathx [OPTIONS] [DIRECTORY]

Arguments:
  DIRECTORY             Directory to scan (default: current directory)

Options:
  -e, --exclude DIR     Additional directories to exclude (can be repeated)
  -m, --max-size BYTES  Skip files larger than this (default: 1MB)
  --no-missing-check    Disable checking for missing relative paths
  --only-missing        Only check for missing relative paths
  -v, --version         Show version and exit
  -h, --help           Show this message and exit
```

## Default Excludes

PathX automatically skips these directories:
- `.git`
- `node_modules`
- `__pycache__`
- `venv`, `.venv`
- `build`, `dist`
- `.tox`
- `eggs`, `.egg-info`

## Severity Levels

Findings are categorized by severity:

| Severity | Description | Examples |
|----------|-------------|----------|
| **Critical** | User-specific paths that will definitely break | `/home/user/...`, `/Users/john/...` |
| **High** | System paths that may vary between installations | `/usr/local/...`, `/opt/...`, UNC paths |
| **Medium** | Temp/cache paths that may cause issues | `/tmp/...`, `/var/tmp/...` |
| **Low** | Informational - might be intentional | Generic absolute paths |
| **Info** | Environment variable references (may be OK) | `$HOME/...`, `%APPDATA%\...` |

## Use Cases

### Before Committing
```bash
# Run pathx before committing to catch path issues
pathx && git commit -m "my changes"
```

### In CI/CD
```yaml
# GitHub Actions example
- name: Check for hardcoded paths
  run: |
    pip install pathx
    pathx --no-missing-check  # Or with missing checks if files should exist
```

### Fresh Clone Verification
```bash
# After cloning a repo, check if all referenced files exist
git clone https://github.com/user/project.git
cd project
pathx
```

## For Beginners

If you're new to coding and wondering why your code works on your computer but not when you share it:

1. **Absolute paths** like `/Users/yourname/project/data.csv` include your username and computer's file structure
2. When someone else runs your code, they don't have the same paths
3. Use **relative paths** like `data/data.csv` instead, and make sure the files are included in your project

PathX helps you find and fix these issues automatically!

## For Experienced Developers

PathX is designed to catch the paths you might miss during code review:
- Paths that snuck in during quick debugging
- Config files with developer-specific settings
- Build scripts with hardcoded installation paths
- Test files referencing local fixtures

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT License - see LICENSE file for details.
