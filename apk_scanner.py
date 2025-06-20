"""
APK Secret Scanner - Final Version
===================================

This script scans an APK file (or an already extracted APK directory) for sensitive data such as
API keys, secrets, credentials, and embedded tokens in both text and binary files. It also generates
a styled, mobile-friendly HTML report of the findings.

Features:
---------
1. Detects secrets using regex patterns:
   - Google API Key, Firebase, AWS Keys, JWT, Stripe Keys, Slack Tokens, Passwords, etc.
2. Scans both text and binary files for sensitive information.
3. Base64-encoded value detection and decoding (UI/CSS/False Positive heuristics applied).
4. Detects obfuscation hints (e.g., Proguard, R8).
5. Skips known non-sensitive files (images, fonts, stylesheets, etc.).
6. Highlights files with sensitive extensions like `.pem`, `.key`, `.crt`.
7. Generates a beautiful, dark-themed HTML report with:
   - Categorized findings
   - Base64 value table
   - Binary section
   - Obfuscation flag
   - File-level sensitive file listing
8. Handles both `.apk` file or an extracted folder as input via CLI.
9. Minimal dependencies (`re`, `os`, `zipfile`, `tqdm`, `argparse`).
10. Graceful error handling and informative logs.

Usage:
------
- To scan an APK:
    python apk_secret_scanner.py --apk path/to/app.apk

- To scan an already extracted folder:
    python apk_secret_scanner.py --dir path/to/folder

Output:
-------
- An HTML report is saved to `apk_scan_report.html` by default (customizable via `--output`).
"""

import os
import re
import base64
import zipfile
import argparse
import logging
from tqdm import tqdm
from datetime import datetime
from html import escape

# Logging setup
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')

# Regex patterns for various secret types
SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Firebase Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key": r"(?i)aws(?:.{0,20})?(?:secret|private)?(?:.{0,20})?['\"][^\s'\"]{40,}['\"]",
    "JWT": r"eyJ[0-9a-zA-Z-_]+?\.[0-9a-zA-Z-_]+?\.[0-9a-zA-Z-_.+/=]*",
    "Stripe Secret Key": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Stripe Publishable Key": r"pk_(?:live|test)_[0-9a-zA-Z]{24,}",
    "Slack Token": r"xox(?:b|a|p|r|s)-[0-9a-zA-Z]{10,48}",
    "Generic API Key": r"(?i)(?:api|apikey|secret|token)[\s:=\"']{1,3}([^\s\"'<>]{16,})",
    "Private Key": r"-----BEGIN (?:RSA|DSA|EC|PGP|PRIVATE) KEY-----",
    "Username": r"(?i)(username|user|uname)[\s:=\"']+([a-zA-Z0-9._-]{3,})",
    "Password": r"(?i)(password|passwd|pwd)[\s:=\"']+([a-zA-Z0-9!@#$%^&*()_+=\-]{4,})",
}
COMPILED_PATTERNS = {k: re.compile(v) for k, v in SENSITIVE_PATTERNS.items()}
BASE64_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")

# Exclusion and detection keywords
EXCLUDED_EXTENSIONS = ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ttf', '.otf', '.eot', '.woff', '.woff2']
SENSITIVE_FILE_EXTENSIONS = ['.pem', '.key', '.crt', '.cer', '.pfx']
COMMON_DEV_KEYWORDS = ['margin', 'padding', 'font-size', 'display']
OBFUSCATION_HINTS = ['proguard', 'r8', 'obfuscator', 'minifyenabled']

def is_text_file(path):
    """
    Heuristically checks whether a file is plain text.
    Returns True/False.
    """
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
            return all(32 <= b <= 126 or b in (9, 10, 13) for b in chunk)
    except:
        return False

def looks_like_dev_code(text):
    """Filter out false positives that look like CSS/UI/dev code."""
    return any(k in text.lower() for k in COMMON_DEV_KEYWORDS)

def try_base64_decode(text):
    """
    Tries to decode a Base64-encoded string and checks if it looks useful.
    Returns decoded text or None.
    """
    try:
        padding = '=' * (-len(text) % 4)
        decoded = base64.b64decode(text + padding).decode('utf-8')
        if decoded and not looks_like_dev_code(decoded):
            return decoded
    except:
        return None

def extract_strings_from_binary(file_path, min_length=3):
    """
    Extracts printable ASCII strings from binary file.
    Returns one large string of newline-separated entries.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            return "\n".join(
                s.decode("utf-8", errors="ignore")
                for s in re.findall(rb"[ -~]{%d,}" % min_length, data)
            )
    except Exception as e:
        logging.warning(f"Binary extract failed: {file_path} - {e}")
        return ""

def scan_content(content, decode_base64=True):
    """
    Scans text content for sensitive values and base64 strings.
    Returns: (list of sensitive tuples), (list of base64 (encoded, decoded) tuples)
    """
    sensitive, base64s = [], []
    for label, pattern in COMPILED_PATTERNS.items():
        for match in pattern.findall(content):
            if isinstance(match, tuple):
                match = next((m for m in match if m), '')
            if not looks_like_dev_code(match):
                sensitive.append((label, match.strip()))
    if decode_base64:
        for b64 in BASE64_REGEX.findall(content):
            decoded = try_base64_decode(b64.strip())
            if decoded:
                base64s.append((b64.strip(), decoded.strip()))
    return sensitive, base64s

def scan_directory(directory):
    """
    Scans a directory (APK folder) for secrets.
    Returns findings list, sensitive file paths list, and obfuscation bool.
    """
    findings, sensitive_files, obfuscated = [], [], set()
    for root, _, files in os.walk(directory):
        for file in tqdm(files, desc=f"Scanning {root}", leave=False):
            ext = os.path.splitext(file)[1].lower()
            full_path = os.path.join(root, file)

            if ext in EXCLUDED_EXTENSIONS:
                continue

            try:
                if is_text_file(full_path):
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for obf in OBFUSCATION_HINTS:
                            if obf.lower() in content.lower():
                                obfuscated.add(obf)
                        s, b = scan_content(content)
                        if s or b:
                            findings.append((full_path, s, b, False))
                else:
                    content = extract_strings_from_binary(full_path)
                    s, _ = scan_content(content, decode_base64=False)
                    if s:
                        findings.append((full_path + " (binary)", s, [], True))

                if ext in SENSITIVE_FILE_EXTENSIONS:
                    sensitive_files.append(full_path)

            except Exception as e:
                logging.warning(f"Error processing {full_path}: {e}")
    return findings, sensitive_files, bool(obfuscated)

def categorize(findings):
    """
    Categorizes sensitive findings by pattern label.
    Input: list of (file, [(label, value)], base64s, is_bin)
    Output: dict[label] = list of (file, value)
    """
    grouped = {}
    for file, sensitive, _ in findings:
        for label, val in sensitive:
            grouped.setdefault(label, []).append((file, val))
    return grouped

def generate_html_report(findings, output, sensitive_files, obfuscated, target):
    """
    Generates a categorized HTML report.
    Inputs:
        - findings: all matched secret data
        - output: report file path
        - sensitive_files: found .pem/.key/etc.
        - obfuscated: bool
        - target: directory scanned
    """
    text_findings = [(f, s, b) for f, s, b, is_bin in findings if not is_bin]
    binary_findings = [(f, s, b) for f, s, b, is_bin in findings if is_bin]
    categories = categorize(text_findings)
    binary_categories = categorize(binary_findings)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = ["""<html><head><title>APK Secret Scanner</title><style>
body{font-family:Arial;background:#121212;color:#e0f7fa;padding:1em}
summary{cursor:pointer;font-size:1.1em;color:#4dd0e1;margin:10px 0}
table{border-collapse:collapse;width:100%;margin:10px 0}
th,td{border:1px solid #444;padding:6px}th{background:#0288d1;color:white}
code{word-wrap:break-word;color:#81d4fa}
.binary-section{border:2px dashed #4dd0e1;padding:15px;margin:20px 0;background:#1a1a1a}
</style></head><body>""",
            f"<h1>Scan Report: {escape(target)}</h1><p>Generated: {now}</p>",
            f"<p><b>Obfuscation:</b> {'Yes' if obfuscated else 'No'}</p>"]

    if sensitive_files:
        html.append(f'<details open><summary>Sensitive Files ({len(sensitive_files)})</summary><ul>')
        html.extend(f"<li>{escape(file)}</li>" for file in sensitive_files)
        html.append("</ul></details>")

    for label, matches in categories.items():
        html.append(f'<details><summary>{escape(label)} ({len(matches)})</summary><table>')
        html.append("<tr><th>File</th><th>Value</th></tr>")
        for file, val in matches:
            html.append(f"<tr><td>{escape(file)}</td><td><code>{escape(val)}</code></td></tr>")
        html.append("</table></details>")

    for file, _, base64s in text_findings:
        if base64s:
            html.append(f'<details><summary>Base64 in {escape(file)} ({len(base64s)})</summary><table>')
            html.append("<tr><th>Encoded</th><th>Decoded</th></tr>")
            for enc, dec in base64s:
                html.append(f"<tr><td><code>{escape(enc)}</code></td><td><code>{escape(dec)}</code></td></tr>")
            html.append("</table></details>")

    if binary_categories:
        html.append('<div class="binary-section"><h2>Binary File Findings</h2>')
        for label, matches in binary_categories.items():
            html.append(f'<details><summary>{escape(label)} ({len(matches)})</summary><table>')
            html.append("<tr><th>Binary File</th><th>Value</th></tr>")
            for file, val in matches:
                html.append(f"<tr><td>{escape(file)}</td><td><code>{escape(val)}</code></td></tr>")
            html.append("</table></details>")
        html.append('</div>')

    html.append("</body></html>")
    with open(output, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html))

def unzip_apk(apk_path, extract_dir):
    """
    Unzips an APK (which is a ZIP) to a folder.
    """
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)

def main():
    """
    Entry point — parses CLI arguments and initiates scan.
    """
    parser = argparse.ArgumentParser(description="APK/Directory Secret Scanner")
    parser.add_argument("--apk", help="Path to APK file")
    parser.add_argument("--dir", help="Path to extracted folder")
    parser.add_argument("--output", default="apk_scan_report.html", help="HTML output report path")
    args = parser.parse_args()

    if not args.apk and not args.dir:
        logging.error("Provide --apk or --dir")
        return

    if args.apk:
        path = args.apk
        extract_to = os.path.basename(path)
        os.makedirs(extract_to, exist_ok=True)
        logging.info("Unzipping APK...")
        unzip_apk(path, extract_to)
        target = extract_to
    else:
        target = args.dir

    logging.info("Scanning...")
    findings, sensitive_files, obfuscated = scan_directory(target)
    generate_html_report(findings, args.output, sensitive_files, obfuscated, target)
    logging.info(f"Scan complete! Report saved to: {args.output}")

if __name__ == "__main__":
    main()
