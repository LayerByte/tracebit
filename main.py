from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import platform
import re
import socket
import ssl
import subprocess
import sys
import urllib.request
from pathlib import Path

PROJECT_NAME = "Tracebit"
PROJECT_FOCUS = "File integrity monitor using SHA-256 baselines."

SECRET_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{20,}"),
]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_entropy(path: Path) -> float:
    data = path.read_bytes()
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def inspect_file(path: Path) -> None:
    if not path.is_file():
        raise ValueError(f"File not found: {path}")
    stat = path.stat()
    header = path.read_bytes()[:16].hex(" ")
    print(f"Project: {PROJECT_NAME}")
    print(f"Focus: {PROJECT_FOCUS}")
    print(f"Path: {path.resolve()}")
    print(f"Size: {stat.st_size} bytes")
    print(f"SHA-256: {sha256_file(path)}")
    print(f"Entropy: {file_entropy(path):.4f}")
    print(f"Header: {header}")


def analyze_log(path: Path, keyword: str | None) -> None:
    if not path.is_file():
        raise ValueError(f"Log file not found: {path}")
    total = 0
    matched = 0
    levels = collections.Counter()
    for line in path.read_text(errors="replace").splitlines():
        total += 1
        upper = line.upper()
        for level in ("ERROR", "WARN", "FAILED", "DENIED", "INFO"):
            if level in upper:
                levels[level] += 1
        if keyword and keyword.lower() in line.lower():
            matched += 1
            print(line[:300])
    print(f"Lines: {total}")
    if keyword:
        print(f"Keyword matches: {matched}")
    print("Levels:", dict(levels))


def validate_json(path: Path) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    print("Valid JSON")
    print(f"Top-level type: {type(data).__name__}")
    if isinstance(data, dict):
        print(f"Keys: {', '.join(sorted(map(str, data.keys()))[:20])}")


def dns_lookup(host: str) -> None:
    if not host or "/" in host:
        raise ValueError("Enter a hostname, not a URL or network range.")
    for family, _, _, _, sockaddr in socket.getaddrinfo(host, None):
        label = "IPv6" if family == socket.AF_INET6 else "IPv4"
        print(f"{label}: {sockaddr[0]}")


def tls_certificate(host: str, port: int) -> None:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=host) as secure:
            cert = secure.getpeercert()
    print(f"Subject: {cert.get('subject')}")
    print(f"Issuer: {cert.get('issuer')}")
    print(f"Valid from: {cert.get('notBefore')}")
    print(f"Valid until: {cert.get('notAfter')}")


def http_headers(url: str) -> None:
    if not url.startswith(("https://", "http://")):
        raise ValueError("URL must start with http:// or https://")
    request = urllib.request.Request(url, headers={"User-Agent": f"{PROJECT_NAME}/1.0"})
    with urllib.request.urlopen(request, timeout=8) as response:
        headers = dict(response.headers.items())
    security_headers = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"]
    for key in security_headers:
        print(f"{key}: {headers.get(key, 'missing')}")


def system_report() -> None:
    print(f"System: {platform.platform()}")
    print(f"Python: {platform.python_version()}")
    print(f"CPU count: {os.cpu_count()}")
    print(f"Hostname: {socket.gethostname()}")


def network_report() -> None:
    system_report()
    print("Local addresses:")
    for result in socket.getaddrinfo(socket.gethostname(), None):
        print(f"- {result[4][0]}")


def route_report() -> None:
    command = ["route", "print"] if os.name == "nt" else ["netstat", "-rn"]
    completed = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
    print(completed.stdout[:5000] or completed.stderr[:1000])


def secret_scan(path: Path) -> None:
    if path.is_file():
        files = [path]
    elif path.is_dir():
        files = [item for item in path.rglob("*") if item.is_file() and item.stat().st_size < 2_000_000]
    else:
        raise ValueError(f"Path not found: {path}")
    findings = 0
    for file_path in files:
        text = file_path.read_text(errors="ignore")
        for pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                findings += 1
                print(f"{file_path}: possible secret-like value near character {match.start()}")
    print(f"Findings: {findings}")


def permission_report(path: Path) -> None:
    if not path.exists():
        raise ValueError(f"Path not found: {path}")
    stat = path.stat()
    print(f"Path: {path.resolve()}")
    print(f"Mode: {oct(stat.st_mode)}")
    print(f"Readable: {os.access(path, os.R_OK)}")
    print(f"Writable: {os.access(path, os.W_OK)}")
    print(f"Executable: {os.access(path, os.X_OK)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=PROJECT_FOCUS)
    parser.add_argument("--file", type=Path, help="Local file to inspect or analyze")
    parser.add_argument("--dir", type=Path, help="Local directory for source or permission analysis")
    parser.add_argument("--host", help="Hostname for DNS or TLS inspection")
    parser.add_argument("--url", help="Website URL for header checks")
    parser.add_argument("--keyword", help="Optional log keyword filter")
    parser.add_argument("--port", type=int, default=443, help="TLS port")
    parser.add_argument("--mode", choices=["auto", "file", "log", "json", "dns", "tls", "headers", "system", "network", "routes", "secrets", "permissions"], default="auto")
    args = parser.parse_args()

    try:
        mode = args.mode
        if mode == "auto":
            lower = PROJECT_NAME.lower()
            if "log" in lower:
                mode = "log"
            elif "json" in lower:
                mode = "json"
            elif "dns" in lower:
                mode = "dns"
            elif "cert" in lower:
                mode = "tls"
            elif "header" in lower:
                mode = "headers"
            elif "route" in lower:
                mode = "routes"
            elif "secret" in lower or "ioc" in lower:
                mode = "secrets"
            elif "permission" in lower:
                mode = "permissions"
            elif "net" in lower:
                mode = "network"
            elif "pulse" in lower:
                mode = "system"
            else:
                mode = "file"

        target_path = args.file or args.dir or Path(".")
        if mode == "file":
            inspect_file(args.file or target_path)
        elif mode == "log":
            analyze_log(args.file or target_path, args.keyword)
        elif mode == "json":
            validate_json(args.file or target_path)
        elif mode == "dns":
            dns_lookup(args.host or "example.com")
        elif mode == "tls":
            tls_certificate(args.host or "example.com", args.port)
        elif mode == "headers":
            http_headers(args.url or "https://example.com")
        elif mode == "system":
            system_report()
        elif mode == "network":
            network_report()
        elif mode == "routes":
            route_report()
        elif mode == "secrets":
            secret_scan(target_path)
        elif mode == "permissions":
            permission_report(target_path)
        return 0
    except Exception as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
