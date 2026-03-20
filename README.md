\# Postgres Audit Toolkit



\*\*CLI tool that audits PostgreSQL databases for security \& compliance risks.\*\*



Built for fintech security \& compliance teams (Moniepoint, Flutterwave, Paystack style).



\## Features

\- Privilege \& role auditing (SUPERUSER detection)

\- PII column scanning

\- Clean error handling

\- Rich CLI + JSON output

\- Maps findings to PCI DSS, SOC 2, NDPA



\## Quick Start



```bash

pip install -e .

pg-audit scan "postgresql://user:pass@localhost:5432/mydb"





For JSON output:



pg-audit scan "postgresql://..." --json



\*\*Demo\*\*



Run `scripts/setup\_insecure\_db.py` to create a vulnerable test database.



\*\*Small. Fast. Production-ready.\*\*





\*\*Test it:\*\*



```bash

pip install -e .

