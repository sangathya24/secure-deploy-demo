# secure-deploy-demo

A small scanner and a before/after demo for **AI-built ("vibe-coded") apps**. It catches two common problems before an app reaches production:

1. **Hardcoded secrets** (cloud keys, private keys, passwords and tokens in source)
2. **Unprotected API routes** (FastAPI endpoints with no authentication)

The demo shows the full path: scan, fix, containerize, gate in CI, deploy to AWS.

## What's here

| Path | Purpose |
| --- | --- |
| `app/vulnerable_app.py` | Deliberately insecure customer portal (hardcoded keys, no login). Never deploy. |
| `app/secure_app.py` | Same app, fixed: secrets from the environment, bearer-token auth on data routes. |
| `scanner/scan.py` | Standard-library-only scanner. Exits 1 on findings so CI can block a deploy. |
| `tests/test_scan.py` | 18 tests covering detection, false positives and exit codes. |
| `Dockerfile` | Ships only the secure app, runs as a non-root user. |
| `.github/workflows/ci.yml` | Runs tests, scans the shipped app, proves the scanner still catches the vulnerable one. Includes a commented Day-2 AWS deploy job. |

## Quick start

```bash
python -m pytest                              # scanner tests (no extra packages needed beyond pytest)
python -m scanner.scan app/vulnerable_app.py  # 5 findings, exit code 1
python -m scanner.scan app/secure_app.py      # clean, exit code 0
python -m scanner.scan app/ --json            # machine-readable output
```

To run the apps themselves:

```bash
pip install -r requirements-dev.txt
API_TOKEN=local-dev-token uvicorn app.secure_app:app --port 8080
curl localhost:8080/health                                              # 200, public
curl localhost:8080/customers                                           # 401
curl -H "Authorization: Bearer local-dev-token" localhost:8080/customers  # 200
```

Suppress a reviewed false positive with `# scan: ignore` on the line.

## Day 2: deploy to AWS (your checklist)

Stay inside free-tier services and tear everything down after recording your demo.

- [ ] Build the image and push it to **ECR**
- [ ] Run it on **App Runner** (simplest) or **ECS Fargate**
- [ ] Store `API_TOKEN` in **Secrets Manager** and inject it as an environment variable
- [ ] Send container logs to **CloudWatch** and add one alarm (for example, spike in 401s)
- [ ] Replace the bearer token check with **Cognito** JWT validation (stretch)
- [ ] Switch CI to deploy using **GitHub OIDC** (no stored AWS keys) via the commented job
- [ ] Take screenshots, then **delete the stack** to avoid charges

## Day 3: package it

- Architecture diagram: GitHub Actions to ECR to App Runner, with Secrets Manager and CloudWatch
- 2-minute demo video: scan the vulnerable app, fix it, CI turns green, deploy
- Optional: wrap the scanner as a small **MCP server** so a coding agent can call "scan this app" before deploying

## Limitations (say these out loud in interviews)

- The scanner uses regexes and the Python AST. It is not a replacement for tools like Semgrep, gitleaks or Bandit.
- Route detection understands common FastAPI patterns (`Depends`, `Security`, `dependencies=[...]`, app/router-level). It does not follow custom decorators or middleware-based auth.
- A bearer token from an environment variable shows the idea. Real deployments need per-user identity (SSO, OIDC).

## Interview talking points

1. **What broke:** an app with an exposed customer export and hardcoded keys, the exact failure mode customers describe with AI-built internal tools.
2. **How I fixed it:** secrets moved to a secret manager, auth on every data route, scan enforced in CI so it cannot regress.
3. **What I'd do for a real customer:** inventory which apps exist, apply one policy (SSO, approved data, audit logs) at deploy time, and monitor continuously.
