# Postgres Audit Toolkit

CLI tool that audits PostgreSQL databases for security vulnerabilities and compliance gaps.

Built for fintech backend teams operating under **PCI DSS**, **SOC 2**, and **Nigeria's NDPA** — where database misconfigurations are a regulatory risk, not just a technical one.

**Disclaimer:** This tool is a screening aid, not a substitute for a professional security audit. Findings should be reviewed by a qualified engineer before any action is taken on a production database.

## Background

Most PostgreSQL databases in production have never been audited. Superuser roles accumulate, PII columns go untracked, and privilege creep happens gradually until it shows up in a compliance review.

This toolkit catches those issues early — locally, in CI, or as part of a security review — without requiring a live connection to production.



## Features

- Detects SUPERUSER roles that violate least-privilege principles
- Flags CREATEROLE and CREATEDB privilege escalation risks
- Scans for unprotected PII columns (email, BVN, NIN, password, passport, SSN)
- Filters built-in PostgreSQL system roles to eliminate false positives
- Rich colored CLI output for humans
- Clean JSON export for CI/CD pipelines
- Mock-based test suite — no live database required to run tests



## Quick Start
```bash
pip install -e .
pg-audit scan "postgresql://user:pass@localhost:5432/mydb"
```

JSON output for pipelines:
```bash
pg-audit scan "postgresql://user:pass@localhost:5432/mydb" --json
```



## Example Output
```
Postgres Audit Toolkit Scan Complete

CRITICAL SUPERUSER role detected
  → Detail: Role 'app_user' has full superuser privileges — least privilege principle violated
  → Control: PCI DSS 7.1 / NDPA Section 24

HIGH Role can create other roles
  → Detail: Role 'power_user' has CREATEROLE privilege — can escalate permissions
  → Control: PCI DSS 7.1 / SOC 2 CC6.3

HIGH Potential PII column without protection
  → Detail: Column 'email' in table 'users' may contain sensitive data
  → Control: NDPA Section 25 / SOC 2 CC6
```



## Built-in Rules

| Rule | Risk | Control |
|------|------|---------|
| Non-system SUPERUSER role detected | CRITICAL | PCI DSS 7.1, NDPA Section 24 |
| Role with CREATEROLE privilege | HIGH | PCI DSS 7.1, SOC 2 CC6.3 |
| Role with CREATEDB privilege | MEDIUM | PCI DSS 7.1 |
| Unprotected PII column | HIGH | NDPA Section 25, SOC 2 CC6 |



## Demo Database

To test the scanner against a vulnerable database:
```bash
# Default connection
python scripts/setup_insecure_db.py

# Custom connection
python scripts/setup_insecure_db.py --url "postgresql://user:pass@localhost:5432/mydb"
```

This creates a superuser role and a users table with PII columns — designed to trigger findings across all rules.



## Running Tests
```bash
pip install pytest
pytest tests/ -v
```

Expected: 12 passing tests. No live database required — all rules are tested using mocks.



## Project Structure
```
pg_audit_toolkit/
    cli.py          # Typer CLI entry point
    connection.py   # Database connection handler
    rules.py        # Audit rule engine
    models.py       # Finding and RiskLevel models
scripts/
    setup_insecure_db.py   # Demo database setup
tests/
    test_rules.py          # Mock-based rule tests
```



## Roadmap

- [ ] Encryption-at-rest detection, flag unencrypted sensitive columns
- [ ] NDPA Article-level rule mapping, make findings directly usable in Nigerian DPA audit responses