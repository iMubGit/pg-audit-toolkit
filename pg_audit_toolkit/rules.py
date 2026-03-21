from pg_audit_toolkit.models import Finding, RiskLevel

RULES = []

SYSTEM_ROLES = {
    'pg_monitor', 'pg_read_all_data', 'pg_write_all_data',
    'pg_read_all_settings', 'pg_read_all_stats', 'pg_stat_scan_tables',
    'pg_signal_backend', 'pg_checkpoint', 'pg_maintain',
    'pg_use_reserved_connections', 'pg_create_subscription',
    'pg_database_owner', 'pg_execute_server_program',
    'pg_read_server_files', 'pg_write_server_files',
    'rds_superuser', 'rdsadmin', 'rdsrepladmin',
    'cloudsqlsuperuser', 'postgres'
}

PII_KEYWORDS = [
    '%email%', '%phone%', '%bvn%', '%nin%', '%password%',
    '%ssn%', '%national_id%', '%passport%', '%dob%', '%date_of_birth%'
]


def register_rule(func):
    RULES.append(func)
    return func


@register_rule
def check_privileges(conn) -> list[Finding]:
    findings = []
    with conn.cursor() as cur:
        cur.execute("SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;")
        for row in cur.fetchall():
            role_name = row[0]
            is_superuser = row[1]

            if role_name in SYSTEM_ROLES:
                continue

            if is_superuser:
                findings.append(Finding(
                    issue="SUPERUSER role detected",
                    risk=RiskLevel.CRITICAL,
                    control="PCI DSS 7.1 / NDPA Section 24",
                    description=f"Role '{role_name}' has full superuser privileges — least privilege principle violated",
                    object=role_name
                ))
    return findings


@register_rule
def check_excessive_privileges(conn) -> list[Finding]:
    findings = []
    with conn.cursor() as cur:
        cur.execute("SELECT rolname, rolcreaterole, rolcreatedb FROM pg_roles;")
        for row in cur.fetchall():
            role_name = row[0]
            can_create_role = row[1]
            can_create_db = row[2]

            if role_name in SYSTEM_ROLES:
                continue

            if can_create_role:
                findings.append(Finding(
                    issue="Role can create other roles",
                    risk=RiskLevel.HIGH,
                    control="PCI DSS 7.1 / SOC 2 CC6.3",
                    description=f"Role '{role_name}' has CREATEROLE privilege — can escalate permissions",
                    object=role_name
                ))

            if can_create_db:
                findings.append(Finding(
                    issue="Role can create databases",
                    risk=RiskLevel.MEDIUM,
                    control="PCI DSS 7.1",
                    description=f"Role '{role_name}' has CREATEDB privilege",
                    object=role_name
                ))
    return findings


@register_rule
def check_pii_columns(conn) -> list[Finding]:
    findings = []
    with conn.cursor() as cur:
        placeholders = ', '.join(['%s'] * len(PII_KEYWORDS))
        cur.execute(f"""
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE column_name ILIKE ANY(ARRAY[{placeholders}])
            AND table_schema NOT IN ('pg_catalog', 'information_schema');
        """, PII_KEYWORDS)
        for row in cur.fetchall():
            findings.append(Finding(
                issue="Potential PII column without protection",
                risk=RiskLevel.HIGH,
                control="NDPA Section 25 / SOC 2 CC6",
                description=f"Column '{row[1]}' in table '{row[0]}' may contain sensitive data",
                object=f"{row[0]}.{row[1]}"
            ))
    return findings