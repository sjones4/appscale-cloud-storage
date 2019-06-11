""" Primes the metadata backend. """

from appscale.cloud_storage.utils import pg_connector


def prime():
    """ Populates the metadata backend with the required tables. """
    with pg_connector.connect() as pg_connection:
        with pg_connection.cursor() as cur:
            cur.execute("""
            CREATE TABLE IF NOT EXISTS buckets (
                project text,
                bucket text,
                created timestamp with time zone default current_timestamp,
                PRIMARY KEY (project, bucket)
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS tokens (
                token text PRIMARY KEY,
                created timestamp with time zone default current_timestamp,
                user_id text,
                expiration timestamp with time zone
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS uploads (
                id text PRIMARY KEY,
                created timestamp with time zone default current_timestamp,
                state text
            );
            """)

            cur.execute("""
            CREATE TABLE IF NOT EXISTS object_metadata (
                bucket text,
                object text,
                created timestamp with time zone default current_timestamp,
                metadata text,
                PRIMARY KEY (bucket, object)
            );
            """)

        pg_connection.commit()
