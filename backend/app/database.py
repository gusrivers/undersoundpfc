import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings


def resolver_database_url() -> str:
    url = (
        getattr(settings, "DATABASE_URL", None)
        or os.getenv("DATABASE_URL")
        or os.getenv("MYSQL_URL")
        or os.getenv("MYSQL_PRIVATE_URL")
    )

    if not url:
        host = os.getenv("MYSQLHOST")
        port = os.getenv("MYSQLPORT", "3306")
        user = os.getenv("MYSQLUSER")
        password = os.getenv("MYSQLPASSWORD")
        database = os.getenv("MYSQLDATABASE")

        if host and user and password and database:
            url = f"mysql://{user}:{quote_plus(password)}@{host}:{port}/{database}"
        else:
            raise ValueError("DATABASE_URL não configurada e variáveis do MySQL não encontradas.")
    if url.startswith("mysql://"):
        url = url.replace("mysql://", "mysql+pymysql://", 1)
    elif url.startswith("mysql2://"):
        url = url.replace("mysql2://", "mysql+pymysql://", 1)

    return url


DATABASE_URL = resolver_database_url()

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine_kwargs = {"connect_args": connect_args}
if not DATABASE_URL.startswith("sqlite"):
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_recycle"] = 1800

engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()