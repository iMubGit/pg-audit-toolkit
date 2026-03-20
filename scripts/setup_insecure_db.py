# Run this to create a vulnerable demo database
import psycopg2

conn = psycopg2.connect("postgresql://postgres:postgres@localhost:5432/demo")
cur = conn.cursor()

cur.execute("CREATE ROLE app_user WITH SUPERUSER LOGIN PASSWORD 'weakpass';")
cur.execute("CREATE TABLE users (id SERIAL, email TEXT, bvn TEXT);")
conn.commit()
print("✅ Insecure demo database created. Run: pg-audit scan postgresql://...")