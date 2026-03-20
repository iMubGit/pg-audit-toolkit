from pg_audit_toolkit.models import Finding, RiskLevel

RULES = []

def register_rule(func):
    RULES.append(func)
    return func

@register_rule
def check_privileges(conn) -> list[Finding]:
    findings = []
    with conn.cursor() as cur:
        cur.execute("SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;")
        for row in cur.fetchall():
            if row[1]:  # rolsuper
                findings.append(Finding(
                    issue="SUPERUSER role detected",
                    risk=RiskLevel.CRITICAL,
                    control="PCI DSS 7.1 / NDPA Section 24",
                    description=f"Role '{row[0]}' has full superuser privileges",
                    object=row[0]
                ))
    return findings

@register_rule
def check_pii_columns(conn) -> list[Finding]:
    findings = []
    with conn.cursor() as cur:
        cur.execute("""
            SELECT table_name, column_name 
            FROM information_schema.columns 
            WHERE column_name ILIKE ANY(ARRAY['%email%', '%phone%', '%bvn%', '%nin%', '%password%']);
        """)
        for row in cur.fetchall():
            findings.append(Finding(
                issue="Potential PII column without protection",
                risk=RiskLevel.HIGH,
                control="NDPA Section 25 / SOC 2 CC6",
                description=f"Column '{row[1]}' in table '{row[0]}' may contain sensitive data",
                object=f"{row[0]}.{row[1]}"
            ))
    return findings