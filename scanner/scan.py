"""secure-deploy-check: a small scanner for AI-built Python/FastAPI apps.

Flags two things that commonly go wrong in "vibe-coded" apps:
  1. hardcoded secrets (cloud keys, private keys, passwords/tokens in source)
  2. FastAPI routes with no authentication

Standard library only. Exits 1 when findings exist, so CI can block a deploy.

Usage:
    python -m scanner.scan app/            # human-readable report
    python -m scanner.scan app/ --json     # machine-readable
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

SKIP_DIRS = {".git", "venv", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".env", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".js", ".ts"}
MAX_FILE_BYTES = 1_000_000

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}
PUBLIC_PATHS = {"/health", "/healthz"}
AUTH_CALLS = {"Depends", "Security"}
APP_FACTORIES = {"FastAPI", "APIRouter"}

IGNORE_MARKER = "scan: ignore"

_NAME = r"[A-Za-z0-9_\-]*"
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    (
        "hardcoded-credential",
        re.compile(
            r"(?i)" + _NAME + r"(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)"
            + _NAME + r"""\s*[:=]\s*["']([^"']{8,})["']"""
        ),
    ),
]


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    rule: str
    message: str


# ---------- secrets ----------

def scan_secrets(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        for rule, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            # URLs assigned to *_token_url style names are not credentials.
            if rule == "hardcoded-credential" and match.group(1).lower().startswith(("http://", "https://")):
                continue
            findings.append(
                Finding(
                    str(path),
                    lineno,
                    "hardcoded-secret",
                    f"Possible {rule.replace('-', ' ')} in source. "
                    "Move it to a secret manager and read it from the environment.",
                )
            )
            break  # one finding per line; never echo the secret value
    return findings


# ---------- routes ----------

def _is_auth_call(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call):
        return False
    fn = node.func
    name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
    return name in AUTH_CALLS


def _protected_app_names(tree: ast.AST) -> set[str]:
    """Names like `app` or `router` created with FastAPI(dependencies=[...])."""
    protected: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            call = node.value
            if isinstance(call, ast.Call):
                fn = call.func
                name = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else None
                if name in APP_FACTORIES and any(kw.arg == "dependencies" for kw in call.keywords):
                    protected.add(node.targets[0].id)
    return protected


def _route_info(func: ast.AST) -> tuple[str, str, str] | None:
    """Return (owner_name, http_method, path) if func is a route handler, else None."""
    for dec in getattr(func, "decorator_list", []):
        if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)):
            continue
        if dec.func.attr not in HTTP_METHODS or not isinstance(dec.func.value, ast.Name):
            continue
        path = ""
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            path = dec.args[0].value
        return dec.func.value.id, dec.func.attr.upper(), path
    return None


def _function_has_auth(func: ast.AST) -> bool:
    args = func.args  # type: ignore[attr-defined]
    defaults = list(args.defaults) + [d for d in args.kw_defaults if d is not None]
    if any(_is_auth_call(d) for d in defaults):
        return True
    for arg in list(args.args) + list(args.kwonlyargs):
        if arg.annotation is not None and any(_is_auth_call(n) for n in ast.walk(arg.annotation)):
            return True  # Annotated[User, Depends(get_user)]
    for dec in func.decorator_list:  # type: ignore[attr-defined]
        if isinstance(dec, ast.Call) and any(kw.arg == "dependencies" for kw in dec.keywords):
            return True
    return False


def scan_routes(path: Path, text: str) -> list[Finding]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    lines = text.splitlines()
    protected = _protected_app_names(tree)
    findings: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        info = _route_info(node)
        if info is None:
            continue
        owner, method, route_path = info
        if route_path in PUBLIC_PATHS or owner in protected or _function_has_auth(node):
            continue
        # allow `# scan: ignore` on the decorator or def line
        first = min([node.lineno] + [d.lineno for d in node.decorator_list])
        if any(IGNORE_MARKER in lines[i - 1] for i in range(first, node.lineno + 1)):
            continue
        findings.append(
            Finding(
                str(path),
                node.lineno,
                "unprotected-route",
                f"{method} {route_path or '<dynamic>'} has no authentication dependency. "
                "Add Depends(...) or app-level dependencies.",
            )
        )
    return findings


# ---------- driver ----------

def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in TEXT_SUFFIXES or p.name.startswith(".env"):
            yield p


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        findings.extend(scan_secrets(path, text))
        if path.suffix == ".py":
            findings.extend(scan_routes(path, text))
    return sorted(findings, key=lambda f: (f.file, f.line, f.rule))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan AI-built apps for hardcoded secrets and unprotected routes.")
    parser.add_argument("paths", nargs="+", type=Path, help="files or directories to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    findings: list[Finding] = []
    for p in args.paths:
        if not p.exists():
            print(f"error: {p} does not exist", file=sys.stderr)
            return 2
        findings.extend(scan_path(p))

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        for f in findings:
            print(f"{f.file}:{f.line}  [{f.rule}]  {f.message}")
        print(f"\n{len(findings)} finding(s)." if findings else "No findings.")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
