import os
import contextlib
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

from app.clients.vault_client import VaultClient

# Create a base class for declarative models
Base = declarative_base()

class Database:
    def __init__(self):
        load_dotenv()
        
        # Get PostgreSQL credentials from environment variables
        # self.host = os.getenv('POSTGRES_HOST', 'localhost')
        # self.port = os.getenv('POSTGRES_PORT', '5432')
        # self.user = os.getenv('POSTGRES_USER', 'postgres')
        # self.password = os.getenv('POSTGRES_PASSWORD')
        # self.dbname = os.getenv('POSTGRES_DB', 'host_configs')
        
        vault = VaultClient(ssl_verify=False)
        _secrets: dict = vault.get_secret('database/postgres')
        
        self.host = _secrets['host']
        self.port = _secrets['port']
        self.user = _secrets['user']
        self.password = _secrets['pass']
        self.dbname = _secrets['dbname']
        
        # Create database if it doesn't exist
        self._create_database_if_not_exists()
        
        # Create SQLAlchemy engine
        self.engine = create_engine(
            f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.dbname}"
        )
        self.Session = sessionmaker(bind=self.engine)
        
        # Create all tables
        Base.metadata.create_all(self.engine)
    
    def _create_database_if_not_exists(self):
        """Create the database if it doesn't exist."""
        # Connect to PostgreSQL server
        conn = psycopg2.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            password=self.password
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        # Create cursor
        cur = conn.cursor()
        
        # Check if database exists
        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (self.dbname,))
        exists = cur.fetchone()
        
        if not exists:
            # Create database
            cur.execute(f'CREATE DATABASE {self.dbname}')
            print(f"Created database {self.dbname}")
        
        # Close connections
        cur.close()
        conn.close()
    
    @contextlib.contextmanager
    def session(self):
        """Provide a transactional scope around a series of operations."""
        session = self.Session()
        try:
            yield session
            session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close() 