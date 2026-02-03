import os
import sys
import json
import csv
import hashlib
import urllib.request
import urllib.error
import zipfile
import shutil
import tempfile
import argparse
import datetime
import re
import tarfile
import stat
import email.utils
from urllib.parse import urljoin
from collections import defaultdict

GITHUB_API_URL = "https://api.github.com/repos/notepad-plus-plus/notepad-plus-plus/releases"
WEBSITE_URL = "https://notepad-plus-plus.org/downloads/"
SEVEN_ZIP_URL = "https://www.7-zip.org/a/7z2409-linux-x64.tar.xz"
NPP_GPG_KEY_URL = "https://notepad-plus-plus.org/gpg/nppGpgPub.asc"

def download_file(url, dest_path):
    """
    Downloads a file with basic HTML detection to avoid 
    saving redirect/error pages as binaries. Preserves remote mtime.
    """
    print(f"Downloading {url}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'NPP-Hasher'})
    try:
        with urllib.request.urlopen(req) as response:
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type:
                 # Check for actual HTML content in the first 500 bytes
                 preview = response.read(500)
                 if b'<html' in preview.lower() or b'<!doctype html' in preview.lower():
                     raise ValueError("Download failed: URL returned HTML (likely 404 or redirect page)")
            
            last_modified = response.headers.get('Last-Modified')
            
            with open(dest_path, 'wb') as out_file:
                # If we read a preview for detection, write it first
                if 'preview' in locals():
                    out_file.write(preview)
                shutil.copyfileobj(response, out_file)
            
            if last_modified:
                try:
                    dt = email.utils.parsedate_to_datetime(last_modified)
                    mtime = dt.timestamp()
                    os.utime(dest_path, (mtime, mtime))
                except Exception as e:
                    print(f"  [!] Failed to set mtime: {e}")

    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ValueError("Download failed: 404 Not Found")
        raise

def ensure_local_7z():
    """
    Bootstraps a local 7zz binary into the project 'bin/' folder
    to ensure we have a modern, capable extractor regardless of the OS.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    bin_dir = os.path.join(base_dir, 'bin')
    local_7zz = os.path.join(bin_dir, '7zz')
    
    if os.path.exists(local_7zz) and os.access(local_7zz, os.X_OK):
        return local_7zz

    print(f"[*] Bootstrapping 7zz to {local_7zz}...")
    os.makedirs(bin_dir, exist_ok=True)
    
    with tempfile.TemporaryDirectory() as td:
        archive_path = os.path.join(td, "7z.tar.xz")
        try:
            download_file(SEVEN_ZIP_URL, archive_path)
            with tarfile.open(archive_path, "r:xz") as tar:
                member = tar.getmember("7zz")
                member.name = "7zz" 
                tar.extract(member, path=bin_dir)
            
            # Ensure the binary is executable
            st = os.stat(local_7zz)
            os.chmod(local_7zz, st.st_mode | stat.S_IEXEC)
            print("[*] Local 7zz installed.")
            return local_7zz
        except Exception as e:
            print(f"[!] Failed to bootstrap 7zz: {e}")
            # Fallback to system tools as a last resort
            system_7z = shutil.which('7za') or shutil.which('7z')
            if system_7z:
                print(f"[*] Using system tool: {system_7z}")
                return system_7z
            sys.exit(1)

def check_dependencies():
    """
    Validates that the required toolset is present.
    Returns: (7zz_path, msiextract_path, gpg_path)
    """
    seven_zip = ensure_local_7z()
    
    msi_tool = shutil.which('msiextract')
    if not msi_tool:
        print("Error: 'msiextract' (from msitools) is required for proper MSI handling.")
        print("Please install it using: sudo dnf install msitools")
        sys.exit(1)
    
    gpg_tool = shutil.which('gpg')
    if not gpg_tool:
        print("Error: 'gpg' is required for signature verification.")
        sys.exit(1)
        
    return seven_zip, msi_tool, gpg_tool

def setup_gpg_key(gpg_tool):
    """
    Bootstraps the official NPP GPG public key into a session-specific keyring.
    """
    gpg_dir = tempfile.mkdtemp(prefix="npp_gpg_")
    key_path = os.path.join(gpg_dir, "npp_key.asc")
    try:
        download_file(NPP_GPG_KEY_URL, key_path)
        print("[*] Importing NPP GPG Public Key...")
        cmd = f'"{gpg_tool}" --homedir "{gpg_dir}" --import "{key_path}" > /dev/null 2>&1'
        if os.system(cmd) != 0:
            raise ValueError("GPG key import failed")
        return gpg_dir
    except Exception as e:
        print(f"[!] GPG Setup failed: {e}")
        shutil.rmtree(gpg_dir, ignore_errors=True)
        return None

def verify_gpg(gpg_tool, gpg_home, data_path, sig_path):
    """
    Verifies a file against its GPG signature.
    Returns: MATCH, MISMATCH, or NO_SIGNATURE.
    """
    if not gpg_home or not os.path.exists(sig_path):
        return "NO_SIGNATURE"
    
    cmd = f'"{gpg_tool}" --homedir "{gpg_home}" --verify "{sig_path}" "{data_path}" > /dev/null 2>&1'
    if os.system(cmd) == 0:
        return "MATCH"
    else:
        return "MISMATCH"

def get_file_info(file_path):
    """
    Extracts file metadata: MD5, SHA1, SHA256, Size, and ISO UTC Date.
    """
    stats = os.stat(file_path)
    hashes = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256()
    }
    
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            for h in hashes.values():
                h.update(chunk)
    
    # Standardize on UTC ISO timestamps
    utc_date = datetime.datetime.fromtimestamp(
        stats.st_mtime, 
        tz=datetime.timezone.utc
    ).isoformat()
    
    return {
        'size': stats.st_size,
        'date': utc_date,
        'hashes': {k: v.hexdigest() for k, v in hashes.items()}
    }

class DebuggableTempDir:
    """
    A context manager that optionally preserves its path if --debug is enabled.
    """
    def __init__(self, debug, prefix="npp_hasher_"):
        self.debug = debug
        self.prefix = prefix
        self.path = None

    def __enter__(self):
        self.path = tempfile.mkdtemp(prefix=self.prefix)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        if not self.debug:
            shutil.rmtree(self.path, ignore_errors=True)
        else:
            print(f"  [DEBUG] Kept temp dir: {self.path}")

def match_version(version, target_pattern):
    """
    Determines if a release version matches the user's requested specifier.
    """
    if target_pattern == "all":
        return True
    if version == target_pattern:
        return True
    
    # Allow 8.9 to match 8.9.0
    if target_pattern.endswith('.0') and version == target_pattern[:-2]:
        return True
        
    if version.startswith(target_pattern + "."):
        return True
        
    return False

def fetch_url_content(url):
    """Retrieves URL content as a decoded string."""
    req = urllib.request.Request(url, headers={'User-Agent': 'NPP-Hasher'})
    try:
        with urllib.request.urlopen(req) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return None

def fetch_github_releases(target_version):
    """Pulls release metadata from the GitHub API."""
    releases = []
    page = 1
    print("[*] Fetching GitHub releases...")
    while True:
        url = f"{GITHUB_API_URL}?per_page=100&page={page}"
        req = urllib.request.Request(url, headers={'User-Agent': 'NPP-Hasher'})
        try:
            with urllib.request.urlopen(req) as response:
                batch = json.loads(response.read().decode())
                if not batch:
                    break
                for r in batch:
                    v = r['tag_name'].lstrip('v')
                    if match_version(v, target_version):
                        r['source'] = 'github'
                        r['version_clean'] = v
                        releases.append(r)
                page += 1
        except Exception:
            break
    return releases

def scrape_website_versions(target_version):
    """Identifies version pages from the official downloads list."""
    print("[*] Scraping website versions...")
    html = fetch_url_content(WEBSITE_URL)
    if not html:
        return []
    
    pattern = re.compile(r'href=["\'](?:https?://notepad-plus-plus\.org)?(/downloads/v([\d.]+)/?)["\']')
    matches = pattern.findall(html)
    
    tasks = []
    seen_urls = set()
    for m in matches:
        url_path, v = m
        if match_version(v, target_version):
            full_url = urljoin(WEBSITE_URL, url_path)
            if full_url not in seen_urls:
                seen_urls.add(full_url)
                tasks.append((v, full_url))
    return tasks

def scrape_website_assets(version, url):
    """Identifies specific download assets on a version page."""
    html = fetch_url_content(url)
    if not html:
        return []
    
    asset_links = []
    # Forensic focus: Binaries, Archives, Signatures, and Checksums
    VALID_EXTS = ('.exe', '.zip', '.7z', '.msi', '.sig', '.asc', '.sha256', '.msix', '.msixbundle')
    link_pattern = re.compile(r'href=["\']([^"\\]+\.[a-zA-Z0-9]+)["\']', re.IGNORECASE)
    
    seen = set()
    for link in link_pattern.findall(html):
        full_link = urljoin(url, link)
        name = full_link.split('/')[-1]
        
        # Skip site assets
        if not any(full_link.lower().endswith(ext) for ext in VALID_EXTS):
            continue
            
        # Filter out web UI links (already have API for that)
        if "github.com" in full_link and "/releases/" in full_link and not any(full_link.endswith(ext) for ext in VALID_EXTS):
            continue

        if full_link not in seen:
            seen.add(full_link)
            asset_links.append({
                'name': name,
                'browser_download_url': full_link,
                'source': 'website'
            })
    return asset_links

def unpack_asset(asset_path, extract_dir, seven_zip_cmd, msi_tool):
    """
    Unpacks assets. 
    For MSI, performs dual-view extraction and timestamp synchronization.
    For EXE (NSIS), synchronizes timestamps from the installer to extracted files.
    """
    if asset_path.lower().endswith('.msi'):
        # 1. Extract human-readable "installed" view
        os.system(f'"{msi_tool}" -C "{extract_dir}" "{asset_path}" > /dev/null 2>&1')
        
        # 2. Extract raw streams for table view and timestamp recovery
        raw_dir = os.path.join(extract_dir, "_raw_msi")
        os.makedirs(raw_dir, exist_ok=True)
        os.system(f'"{seven_zip_cmd}" x "{asset_path}" -o"{raw_dir}" -y -bb0 > /dev/null 2>&1')
        
        # 3. Synchronize timestamps from raw streams to the real files
        hash_to_mtime = {}
        for root, _, files in os.walk(raw_dir):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sha = hashlib.sha256()
                    with open(fp, 'rb') as f_obj:
                        while chunk := f_obj.read(8192):
                            sha.update(chunk)
                    hash_to_mtime[sha.hexdigest()] = os.path.getmtime(fp)
                except:
                    continue
        
        for root, _, files in os.walk(extract_dir):
            if "_raw_msi" in root:
                continue
            for f in files:
                fp = os.path.join(root, f)
                try:
                    sha = hashlib.sha256()
                    with open(fp, 'rb') as f_obj:
                        while chunk := f_obj.read(8192):
                            sha.update(chunk)
                    h = sha.hexdigest()
                    if h in hash_to_mtime:
                        mtime = hash_to_mtime[h]
                        os.utime(fp, (mtime, mtime))
                except:
                    continue
        return True
    
    # Generic archive extraction
    cmd = f'"{seven_zip_cmd}" x "{asset_path}" -o"{extract_dir}" -y -bb0 > /dev/null 2>&1'
    res = os.system(cmd)
    
    # Fallback for standard ZIP files
    if res != 0 and asset_path.endswith('.zip'):
         try:
            with zipfile.ZipFile(asset_path, 'r') as z:
                z.extractall(extract_dir)
            res = 0
         except:
            pass
    
    if res == 0 and asset_path.lower().endswith('.exe'):
        # NSIS extraction often loses timestamps (especially arm64).
        # Sync all extracted files to the installer's timestamp.
        mtime = os.path.getmtime(asset_path)
        for root, _, files in os.walk(extract_dir):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    os.utime(fp, (mtime, mtime))
                except:
                    continue

    return res == 0

def get_arch(filename):
    """Infers architecture from the filename string."""
    lower = filename.lower()
    if 'x64' in lower:
        return 'x64'
    if 'arm64' in lower:
        return 'arm64'
    return 'x86'

def parse_checksums(checksum_path):
    """
    Parses manifest-style checksum files (MD5, SHA1, or SHA256).
    Returns a dict mapping filename -> {algo: hash}.
    """
    found = defaultdict(dict)
    if not os.path.exists(checksum_path):
        return found
    
    with open(checksum_path, 'r') as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 2:
                h = parts[0].strip().lower()
                fname = parts[1].strip().lower()
                
                algo = None
                if len(h) == 32:
                    algo = 'md5'
                elif len(h) == 40:
                    algo = 'sha1'
                elif len(h) == 64:
                    algo = 'sha256'
                
                if algo:
                    found[fname][algo] = h
    return found

def analyze_discrepancies(data_list):
    """
    Compares installers and their contents across all sources for a version group.
    Findings are sorted by filename for better readability.
    """
    findings = []
    installer_map = defaultdict(lambda: {})
    content_map = defaultdict(lambda: {})
    
    for release in data_list:
        src = release['source']
        version = release['version']
        for inst in release['installers']:
            fname = inst['filename']
            # Only analyze files that were actually downloaded
            if 'hashes' in inst:
                # Discrepancy key: version + filename
                installer_key = (version, fname)
                installer_map[installer_key][src] = {
                    'hash': inst['hashes']['sha256'],
                    'obj': inst
                }
                
                arch = inst['arch']
                for content in inst['contents']:
                    norm_path = content['path'].replace('\\', '/').lower()
                    # Discrepancy key: version + arch + internal_path
                    key = (version, arch, norm_path)
                    identifier = f"{src}::{fname}"
                    content_map[key][identifier] = {
                        'hash': content['hashes']['sha256'],
                        'obj': content
                    }
            elif inst.get('verified') == "MISSING (404)":
                msg = f"MISSING: Asset {fname} ({src}, v{version}) returned 404."
                findings.append({
                    'sort_key': (fname.lower(), fname.lower(), ""),
                    'msg': msg
                })

    # 1. Source Discrepancies (Compare same installer across distribution channels)
    for (version, fname), sources in installer_map.items():
        if len(sources) > 1:
            hashes = set(s['hash'] for s in sources.values())
            if len(hashes) > 1:
                msg = f"CRITICAL: Installer {fname} (v{version}) differs between sources: {list(sources.keys())}"
                print(f"  [!!!] {msg}")
                findings.append({
                    'sort_key': (fname.lower(), fname.lower(), ""),
                    'msg': msg
                })
                for s in sources.values():
                    s['obj']['discrepancy_note'] = "Source hash mismatch"
            else:
                 for s in sources.values():
                    s['obj']['discrepancy_note'] = f"Source verified ({len(sources)} matches)"

    # 2. Content Discrepancies (Compare same binary across different installer types)
    for (version, arch, norm_path), variants in content_map.items():
        if len(variants) > 1:
            hash_groups = defaultdict(list)
            for ident, info in variants.items():
                hash_groups[info['hash']].append(ident)
            
            if len(hash_groups) > 1:
                filename = norm_path.split('/')[-1]
                msg = f"WARNING: Content '{norm_path}' ({arch}, v{version}) has {len(hash_groups)} variants:"
                for h, installers in hash_groups.items():
                    msg += f"\n    Hash {h[:8]}... : {', '.join(sorted(installers))}"
                
                findings.append({
                    'sort_key': (filename.lower(), norm_path.lower(), arch),
                    'msg': msg
                })
                for v in variants.values():
                    v['obj']['discrepancy_note'] = f"Content mismatch ({len(hash_groups)} variants)"

    # Final sort for the report
    findings.sort(key=lambda x: x['sort_key'])
    return [f['msg'] for f in findings]

def save_csv(data, filename):
    """Generates a flat release manifest."""
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = [
            'version', 'source', 'arch', 'installer_name', 
            'path', 'filename', 'internal_name', 
            'file_size', 'file_date', 
            'md5', 'sha1', 'sha256', 
            'dist_hash_status', 'dist_gpg_status', 'discrepancy_note', 'url'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for release in data:
            for installer in release['installers']:
                row_base = {
                    'version': release['version'],
                    'source': release['source'],
                    'arch': installer['arch'],
                    'installer_name': installer['filename'],
                    'file_size': installer.get('size', '0'),
                    'file_date': installer.get('date', ''),
                    'md5': installer.get('hashes', {}).get('md5', ''),
                    'sha1': installer.get('hashes', {}).get('sha1', ''),
                    'sha256': installer.get('hashes', {}).get('sha256', ''),
                    'dist_hash_status': installer['verified'],
                    'dist_gpg_status': installer.get('gpg_status', 'N/A'),
                    'discrepancy_note': installer.get('discrepancy_note', ''),
                    'url': installer.get('url', ''),
                    'internal_name': ''
                }
                
                # Write installer row
                writer.writerow({**row_base, 'path': '', 'filename': installer['filename']})
                
                # Write individual file rows
                for content in installer.get('contents', []):
                    writer.writerow({
                        **row_base, 
                        'path': content['path'], 
                        'filename': content['filename'], 
                        'file_size': content['size'], 
                        'file_date': content['date'], 
                        'md5': content['hashes']['md5'], 
                        'sha1': content['hashes']['sha1'], 
                        'sha256': content['hashes']['sha256'], 
                        'dist_hash_status': 'N/A', 
                        'dist_gpg_status': 'N/A',
                        'discrepancy_note': content.get('discrepancy_note', ''),
                        'internal_name': content.get('internal_name', '')
                    })
    print(f"Saved CSV: {filename}")

def save_file_centric_json(data_list, filename):
    """Generates a JSON indexed by content hash, sorted by filename."""
    file_map = {}
    for release in data_list:
        for inst in release['installers']:
            for content in inst.get('contents', []):
                sha = content['hashes']['sha256']
                if sha not in file_map:
                    file_map[sha] = {
                        'md5': content['hashes']['md5'],
                        'sha1': content['hashes']['sha1'],
                        'sha256': sha,
                        'size': content['size'],
                        'occurrences': []
                    }
                
                occ = {
                    'version': release['version'],
                    'source': release['source'],
                    'arch': inst['arch'],
                    'installer': inst['filename'],
                    'path': content['path'],
                    'date': content['date'],
                    'dist_hash_status': inst['verified'],
                    'dist_gpg_status': inst.get('gpg_status', 'N/A')
                }
                if 'internal_name' in content:
                    occ['internal_name'] = content['internal_name']
                
                file_map[sha]['occurrences'].append(occ)
    
    def get_sort_key(item):
        sha, info = item
        first_occ = info['occurrences'][0]
        path = first_occ['path'].replace('\\', '/')
        fname = path.split('/')[-1].lower()
        return (fname, path.lower(), sha)

    sorted_items = sorted(file_map.items(), key=get_sort_key)
    with open(filename, 'w') as f:
        json.dump(dict(sorted_items), f, indent=2)
    print(f"Saved File-Centric JSON: {filename}")

def main():
    parser = argparse.ArgumentParser(description="Notepad++ Release Hasher")
    parser.add_argument("-v", "--version", required=True, help="Version specifier (e.g. '8', 'all')")
    parser.add_argument("-a", "--arch", nargs="+", help="Architectures. Default: all")
    parser.add_argument("--output-dir", default="report", help="Output directory")
    parser.add_argument("--debug", action="store_true", help="Keep extracted files")
    args = parser.parse_args()
    
    # Initialize tools and trust
    seven_zip_cmd, msi_tool, gpg_tool = check_dependencies()
    gpg_home = setup_gpg_key(gpg_tool)
    os.makedirs(args.output_dir, exist_ok=True)
    
    grouped_results = {}
    processed_urls = set()

    # 1. Process GitHub Distribution Channel
    gh_releases = fetch_github_releases(args.version)
    for r in gh_releases:
        v = r['version_clean']
        group_key = "v" + ".".join(v.split('.')[:2])
        if group_key not in grouped_results:
            grouped_results[group_key] = []
            
        rel_obj = {'version': v, 'source': 'github', 'installers': []}
        
        # Step A: Collect Metadata Assets (Hashes & Signatures)
        all_expected_hashes = defaultdict(dict)
        meta_assets = {}
        
        with DebuggableTempDir(args.debug, prefix=f"npp_meta_{v}_") as td_meta:
            for asset in r['assets']:
                name_lower = asset['name'].lower()
                is_meta = any(ext in name_lower for ext in ['.checksums', '.sha256', '.sha1', '.md5', '.sig', '.asc'])
                if is_meta:
                    p = os.path.join(td_meta, asset['name'])
                    try:
                        download_file(asset['browser_download_url'], p)
                        meta_assets[asset['name']] = p
                    except:
                        pass
            
            # Step B: Parse all discovered manifests
            for name, path in meta_assets.items():
                is_manifest = any(ext in name.lower() for ext in ['.checksums', '.sha256', '.sha1', '.md5'])
                if is_manifest and not name.lower().endswith(('.sig', '.asc')):
                    parsed = parse_checksums(path)
                    for fn, algos in parsed.items():
                        all_expected_hashes[fn].update(algos)
                    
                    # Fallback for single-hash standalone files
                    if not parsed:
                        try:
                            with open(path, 'r') as f:
                                h = f.read().strip().split()[0].lower()
                                algo = 'md5' if len(h) == 32 else 'sha1' if len(h) == 40 else 'sha256' if len(h) == 64 else None
                                if algo:
                                    all_expected_hashes[name.rsplit('.', 1)[0].lower()][algo] = h
                        except:
                            pass
            
            # Step C: Process Release Binaries
            for asset in r['assets']:
                name = asset['name']
                url = asset['browser_download_url']
                
                # Metadata is already handled
                if any(ext in name.lower() for ext in ['.sig', '.asc', '.sha256', '.md5', '.sha1', '.checksums']):
                    continue
                if args.arch and not any(a in name.lower() for a in args.arch):
                    continue
                    
                processed_urls.add(url)
                
                with DebuggableTempDir(args.debug, prefix=f"npp_{name}_") as td_asset:
                    p = os.path.join(td_asset, name)
                    try:
                        download_file(url, p)
                        info = get_file_info(p)
                        
                        # Validation: Strict Multi-Hash Check
                        status = "UNCHECKED"
                        target_hashes = all_expected_hashes.get(name.lower(), {})
                        if target_hashes:
                            mismatch = False
                            checked = False
                            for algo, expected in target_hashes.items():
                                actual = info['hashes'].get(algo)
                                if actual:
                                    checked = True
                                    if actual.lower() != expected.lower():
                                        mismatch = True
                                        break
                            status = "MISMATCH" if mismatch else "MATCH" if checked else "UNCHECKED"
                            if status == "MISMATCH":
                                print(f"  [CRITICAL] Hash Mismatch detected for {name}")
                        
                        # Validation: GPG Signature Check
                        gpg_status = "UNCHECKED"
                        for s_name in [f"{name}.sig", f"{name}.asc"]:
                            if s_name in meta_assets:
                                gpg_status = verify_gpg(gpg_tool, gpg_home, p, meta_assets[s_name])
                                break
                        
                        inst_obj = {
                            'filename': name, 'arch': get_arch(name), 'size': info['size'], 
                            'date': info['date'], 'hashes': info['hashes'], 
                            'verified': status, 'gpg_status': gpg_status, 
                            'url': url, 'contents': []
                        }
                        
                        # Step D: Container Deep-Dive
                        is_container = name.lower().endswith(('.exe', '.zip', '.7z', '.msi', '.tar', '.xz', '.gz'))
                        if is_container:
                            ext_dir = os.path.join(td_asset, "ext")
                            os.makedirs(ext_dir, exist_ok=True)
                            if unpack_asset(p, ext_dir, seven_zip_cmd, msi_tool):
                                for root, _, files in os.walk(ext_dir):
                                    for f in files:
                                        fp = os.path.join(root, f)
                                        fi = get_file_info(fp)
                                        inst_obj['contents'].append({
                                            'path': os.path.relpath(fp, ext_dir),
                                            'filename': f,
                                            'size': fi['size'],
                                            'date': fi['date'],
                                            'hashes': fi['hashes']
                                        })
                                inst_obj['contents'].sort(key=lambda x: x['filename'].lower())
                            else:
                                print(f"  [!!!] CRITICAL: Extraction FAILED for container {name}")
                                sys.exit(1)
                        
                        rel_obj['installers'].append(inst_obj)
                        
                    except Exception as e:
                        if "404" in str(e):
                            rel_obj['installers'].append({
                                'filename': name, 'arch': get_arch(name), 
                                'verified': "MISSING (404)", 'url': url, 
                                'discrepancy_note': "Upstream purge detected"
                            })
                        else:
                            print(f"Error processing GitHub {name}: {e}")
                            sys.exit(1)
                            
        if rel_obj['installers']:
            grouped_results[group_key].append(rel_obj)

    # 2. Process Website Distribution Channel
    web_versions = scrape_website_versions(args.version)
    for v, url in web_versions:
        print(f"\n[*] Processing Website Version: {v} ({url})")
        group_key = "v" + ".".join(v.split('.')[:2])
        if group_key not in grouped_results:
            grouped_results[group_key] = []
            
        rel_obj = {'version': v, 'source': 'website', 'installers': []}
        for asset in scrape_website_assets(v, url):
            name = asset['name']
            dl_url = asset['browser_download_url']
            
            if args.arch and not any(a in name.lower() for a in args.arch):
                continue
            if dl_url in processed_urls:
                continue
            
            processed_urls.add(dl_url)
            
            with DebuggableTempDir(args.debug, prefix=f"npp_web_{name}_") as td_web:
                p = os.path.join(td_web, name)
                try:
                    download_file(dl_url, p)
                    info = get_file_info(p)
                    inst_obj = {
                        'filename': name, 'arch': get_arch(name), 'size': info['size'], 
                        'date': info['date'], 'hashes': info['hashes'], 
                        'verified': "UNCHECKED", 'url': dl_url, 'contents': []
                    }
                    
                    is_container = name.lower().endswith(('.exe', '.zip', '.7z', '.msi', '.tar', '.xz', '.gz'))
                    if is_container:
                        ext_dir = os.path.join(td_web, "ext")
                        os.makedirs(ext_dir, exist_ok=True)
                        if unpack_asset(p, ext_dir, seven_zip_cmd, msi_tool):
                            for root, _, files in os.walk(ext_dir):
                                for f in files:
                                    fp = os.path.join(root, f)
                                    fi = get_file_info(fp)
                                    inst_obj['contents'].append({
                                        'path': os.path.relpath(fp, ext_dir),
                                        'filename': f,
                                        'size': fi['size'],
                                        'date': fi['date'],
                                        'hashes': fi['hashes']
                                    })
                            inst_obj['contents'].sort(key=lambda x: x['filename'].lower())
                        else:
                            print(f"  [!!!] CRITICAL: Extraction FAILED for container {name}")
                            sys.exit(1)
                    rel_obj['installers'].append(inst_obj)
                except Exception as e:
                    if "Download failed" in str(e):
                        rel_obj['installers'].append({
                            'filename': name, 'arch': get_arch(name), 
                            'verified': "MISSING (404/HTML)", 'url': dl_url, 
                            'discrepancy_note': str(e)
                        })
                    else:
                        print(f"Error processing Website {name}: {e}")
                        sys.exit(1)
                        
        if rel_obj['installers']:
            grouped_results[group_key].append(rel_obj)

    # 3. Aggregation & Cross-Version Linking
    all_session_data = []
    for group_key, data in grouped_results.items():
        if not data:
            continue
            
        all_session_data.extend(data)
        unique_versions = sorted(list(set(r['version'] for r in data)))
        file_suffix = f"v{unique_versions[0]}" if len(unique_versions) == 1 else group_key
        
        print(f"\n[*] Analyzing discrepancies for {file_suffix}...")
        discrepancies = analyze_discrepancies(data)
        base_path = os.path.join(args.output_dir, f"npp_hashes_{file_suffix}")
        
        if discrepancies:
            with open(f"{base_path}_report.txt", 'w') as f:
                f.write("\n".join(discrepancies))
            print(f"  [!] Found {len(discrepancies)} discrepancies! See {base_path}_report.txt")
            
        # Write Version-Centric Outputs
        with open(f"{base_path}.json", 'w') as f:
            json.dump(data, f, indent=2)
        save_file_centric_json(data, f"{base_path}_file_centric.json")
        save_csv(data, f"{base_path}.csv")

    # Final Global tracking link
    if all_session_data:
        global_path = os.path.join(args.output_dir, "npp_hashes_global_file_centric.json")
        print(f"\n[*] Generating global session tracking report...")
        save_file_centric_json(all_session_data, global_path)

    # Cleanup Trust
    if gpg_home:
        shutil.rmtree(gpg_home, ignore_errors=True)

if __name__ == "__main__":
    main()
