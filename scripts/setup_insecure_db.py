#!/usr/bin/env python3
"""
Setup script to create a vulnerable demo database for testing pg-audit-toolkit.

Usage:
    python scripts/setup_insecure_db.py
    python scripts/setup_insecure_db.py --url postgresql://myuser:mypass@localhost:5432/mydb
"""
import argparse
import sys
import psycopg2

DEFAULT_URL = "postgresql://postgres:postgres@localhost:5432/demo"


def create_insecure_db(db_url: str) -> None:
    try:
        conn = psycopg2.connect(db_url)
        conn.autocommit = True
        cur = conn.cursor()

        cur.execute("""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'app_user') THEN
                    CREATE ROLE app_user WITH SUPERUSER LOGIN PASSWORD 'weakpass';
                END IF;
            END
            $$;
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email TEXT,
                bvn TEXT,
                password TEXT
            );
        """)

        cur.execute("""
            INSERT INTO users (email, bvn, password)
            VALUES ('test@example.com', '12345678901', 'plaintext_password')
            ON CONFLICT DO NOTHING;
        """)

        print(" Insecure demo database created successfully.")
        print(f"   Connected to: {db_url}")
        print("   Created: role 'app_user' (SUPERUSER), table 'users' with PII columns")
        print("\nRun the scanner:")
        print(f"   pg-audit scan \"{db_url}\"")

        cur.close()
        conn.close()

    except psycopg2.OperationalError as e:
        print(f" Connection failed: {str(e)}")
        print("   Make sure PostgreSQL is running and the connection URL is correct.")
        sys.exit(1)
    except Exception as e:
        print(f" Setup failed: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a vulnerable demo PostgreSQL database for testing pg-audit-toolkit"
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_URL,
        help=f"PostgreSQL connection URL (default: {DEFAULT_URL})"
    )
    args = parser.parse_args()
    create_insecure_db(args.url)