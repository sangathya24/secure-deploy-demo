from pathlib import Path

from scanner.scan import main, scan_path

ROOT = Path(__file__).resolve().parent.parent


def write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body)
    return p


def rules(findings):
    return [f.rule for f in findings]


def test_detects_aws_access_key(tmp_path):
    p = write(tmp_path, "a.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    assert rules(scan_path(p)) == ["hardcoded-secret"]


def test_detects_hardcoded_password(tmp_path):
    p = write(tmp_path, "a.py", 'DB_PASSWORD = "Sup3rS3cretPassw0rd!"\n')
    assert rules(scan_path(p)) == ["hardcoded-secret"]


def test_detects_private_key_header(tmp_path):
    p = write(tmp_path, "key.json", '{"k": "-----BEGIN RSA PRIVATE KEY-----"}\n')
    assert rules(scan_path(p)) == ["hardcoded-secret"]


def test_env_lookup_is_not_flagged(tmp_path):
    p = write(tmp_path, "a.py", 'import os\nDB_PASSWORD = os.environ["DB_PASSWORD"]\n')
    assert scan_path(p) == []


def test_url_value_is_not_flagged(tmp_path):
    p = write(tmp_path, "a.py", 'token_url = "https://example.com/oauth/token"\n')
    assert scan_path(p) == []


def test_ignore_marker_suppresses_finding(tmp_path):
    p = write(tmp_path, "a.py", 'KEY = "AKIAIOSFODNN7EXAMPLE"  # scan: ignore\n')
    assert scan_path(p) == []


def test_secret_value_never_appears_in_message(tmp_path):
    p = write(tmp_path, "a.py", 'DB_PASSWORD = "Sup3rS3cretPassw0rd!"\n')
    (finding,) = scan_path(p)
    assert "Sup3rS3cretPassw0rd" not in finding.message


ROUTE_OPEN = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/customers")
def customers():
    return []
'''

ROUTE_DEPENDS = '''
from fastapi import Depends, FastAPI
app = FastAPI()

def user(): ...

@app.get("/customers")
def customers(u=Depends(user)):
    return []
'''

ROUTE_DECORATOR_DEPS = '''
from fastapi import Depends, FastAPI
app = FastAPI()

def user(): ...

@app.get("/customers", dependencies=[Depends(user)])
def customers():
    return []
'''

ROUTE_APP_LEVEL = '''
from fastapi import Depends, FastAPI
def user(): ...
app = FastAPI(dependencies=[Depends(user)])

@app.get("/customers")
def customers():
    return []
'''

ROUTE_ROUTER_LEVEL = '''
from fastapi import APIRouter, Depends
def user(): ...
router = APIRouter(dependencies=[Depends(user)])
open_router = APIRouter()

@router.get("/a")
def a():
    return []

@open_router.get("/b")
def b():
    return []
'''

ROUTE_ANNOTATED = '''
from typing import Annotated
from fastapi import Depends, FastAPI
app = FastAPI()
def user(): ...

@app.get("/customers")
async def customers(u: Annotated[str, Depends(user)]):
    return []
'''

ROUTE_HEALTH = '''
from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
'''


def test_unprotected_route_is_flagged(tmp_path):
    p = write(tmp_path, "a.py", ROUTE_OPEN)
    (finding,) = scan_path(p)
    assert finding.rule == "unprotected-route"
    assert "GET /customers" in finding.message


def test_depends_param_protects_route(tmp_path):
    assert scan_path(write(tmp_path, "a.py", ROUTE_DEPENDS)) == []


def test_decorator_dependencies_protect_route(tmp_path):
    assert scan_path(write(tmp_path, "a.py", ROUTE_DECORATOR_DEPS)) == []


def test_app_level_dependencies_protect_all_routes(tmp_path):
    assert scan_path(write(tmp_path, "a.py", ROUTE_APP_LEVEL)) == []


def test_router_level_dependencies_only_cover_that_router(tmp_path):
    findings = scan_path(write(tmp_path, "a.py", ROUTE_ROUTER_LEVEL))
    assert len(findings) == 1
    assert "GET /b" in findings[0].message


def test_annotated_depends_protects_route(tmp_path):
    assert scan_path(write(tmp_path, "a.py", ROUTE_ANNOTATED)) == []


def test_health_route_may_be_public(tmp_path):
    assert scan_path(write(tmp_path, "a.py", ROUTE_HEALTH)) == []


def test_syntax_error_file_does_not_crash(tmp_path):
    assert scan_path(write(tmp_path, "broken.py", "def (:\n")) == []


def test_vulnerable_demo_is_caught():
    findings = scan_path(ROOT / "app" / "vulnerable_app.py")
    kinds = set(rules(findings))
    assert kinds == {"hardcoded-secret", "unprotected-route"}
    assert len([f for f in findings if f.rule == "unprotected-route"]) == 3
    assert len([f for f in findings if f.rule == "hardcoded-secret"]) == 2


def test_secure_demo_is_clean():
    assert scan_path(ROOT / "app" / "secure_app.py") == []


def test_exit_codes(tmp_path, capsys):
    clean = write(tmp_path, "clean.py", "x = 1\n")
    assert main([str(clean)]) == 0
    assert main([str(ROOT / "app" / "vulnerable_app.py")]) == 1
    assert main([str(tmp_path / "missing.py")]) == 2
    capsys.readouterr()
