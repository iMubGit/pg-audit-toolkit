import psycopg2
from psycopg2 import OperationalError
from urllib.parse import urlparse

def get_connection(db_url: str):
    try:
        result = urlparse(db_url)
        conn = psycopg2.connect(
            dbname=result.path[1:],
            user=result.username,
            password=result.password,
            host=result.hostname,
            port=result.port or 5432
        )
        return conn
    except OperationalError as e:
        raise ConnectionError(f"Failed to connect to database: {str(e)}")