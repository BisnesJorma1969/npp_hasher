# Notepad++ Release Hasher

A tool designed to retrieve, extract, and verify constituent files of Notepad++ releases across multiple sources (GitHub and the official website). This tool helps track and detect modifications or discrepancies in official release packages.

## Features

- **Multi-Source Retrieval**: Simultaneously fetches releases from the GitHub API and scrapes the official Notepad++ website.
- **Strict Multi-Algorithm Verification**: Automatically collects available checksum files (`.sha256`, `.sha1`, `.md5`, `.checksums`). It verifies assets against every matching hash found; if even one algorithm fails, the asset is flagged as a `MISMATCH`.
- **Deep Extraction**:
    - **MSI**: Performs dual extraction—reconstructing the "installed" file tree using `msitools` and extracting raw database tables/streams using `7-zip`. Includes a timestamp synchronization fix.
    - **EXE/ZIP/7z**: Fully unpacks containers to hash individual components.
- **Asset Hashing**: Processes binaries, archives, GPG signatures (`.sig`, `.asc`), and metadata files.
- **Discrepancy Analysis**: Automatically cross-references sources and package types. Discrepancies are grouped by hash in the final report to clearly show which installers align and which are outliers.
- **File-Centric Reporting**: Generates a deduplicated JSON keyed by SHA256, allowing you to see every version and installer where a specific binary has appeared across the entire session.

## Requirements & Platform Support

- **Operating System**: Linux (x86_64 / x64 only).
- **Python 3.9+** (uses only standard library).
- **msitools**: Mandatory for proper MSI database parsing and file recovery.
- **gpg**: Required for signature verification.

### Automatic Tool Bootstrapping
The script automatically downloads a standalone `7zz` (7-Zip) binary for Linux x64 from `7-zip.org` into the `bin/` directory upon first run. This ensures modern extraction capabilities without requiring a system-wide 7-Zip installation.

## Environment Setup

### 1. Install System Dependencies

#### **RHEL / AlmaLinux / CentOS**
```bash
sudo dnf install msitools gpg
```

#### **Ubuntu / Debian**
```bash
sudo apt update
sudo apt install msitools gpg
```

### 2. Project Setup
Simply clone the repository and ensure `npp_hasher.py` is executable:
```bash
chmod +x npp_hasher.py
```

## Usage

### Basic Hashing
Fetch and hash a specific version:
```bash
python3 npp_hasher.py -v 8.9.1
```

### Advanced Version Ranges
- **Specific Version**: `-v 8.9.1`
- **Minor Version Series**: `-v 8.9` (matches 8.9.0, 8.9.1, etc.)
- **Major Version Series**: `-v 8` (matches all v8.x.x)
- **Everything**: `-v all`

### Options
- `--output-dir <dir>`: Specify where to save results (default: `report`).
- `-a <arch>`: Filter by architecture (e.g., `x64 arm64`). Defaults to all.
- `--debug`: Keeps all extracted temporary directories for manual inspection.

## Output Files

The tool generates four files per version group:

1.  **`npp_hashes_v[version].json`**: Hierarchical view (Release -> Installer -> Internal Files).
2.  **`npp_hashes_v[version]_file_centric.json`**: Deduplicated view (SHA256 -> Occurrences). Ideal for tracking binary reuse across versions.
3.  **`npp_hashes_v[version].csv`**: Flat list for spreadsheet analysis, including `internal_name` for MSI streams.
4.  **`npp_hashes_v[version]_report.txt`**: Detailed discrepancy report grouping mismatches by hash.

## Discrepancy Analysis

The `_report.txt` file is the primary output for auditing. It flags:
- **Hash Mismatches**: When a downloaded asset fails to match any of its provided upstream hashes (MD5, SHA1, or SHA256).
- **Source Mismatches**: When the same filename exists across multiple sources (GitHub, Website) but with differing content hashes.
- **Package Inconsistencies**: When a file (e.g., `GUP.exe`) differs between the `.zip`, `.exe`, and `.msi` for the same release.
- **Missing Assets (404)**: Explicitly logs historical assets that have been purged from the developer's server.
- **Failed Extractions**: Containers that cannot be safely unpacked are treated as critical errors.

## License

This project is released into the public domain under the [Unlicense](LICENSE). You are free to copy, modify, publish, use, compile, sell, or distribute this software for any purpose, commercial or non-commercial, and by any means.