import os
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
from urllib.parse import urlparse, urlunparse


def _clean_env(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def resolver_database_url() -> str:
    # 1. Prioriza variáveis de ambiente injetadas pelo Railway/plataforma
    url = (
        _clean_env(os.getenv("DATABASE_URL"))
        or _clean_env(os.getenv("MYSQL_URL"))
        or _clean_env(os.getenv("MYSQL_PRIVATE_URL"))
    )
    print(
        "[DB DEBUG BEFORE RAISE]",
        "DATABASE_URL=", repr(os.getenv("DATABASE_URL")),
        "| MYSQL_PRIVATE_URL=", repr(os.getenv("MYSQL_PRIVATE_URL")),
        "| MYSQLHOST=", repr(os.getenv("MYSQLHOST")),
        "| settings.DATABASE_URL=", repr(getattr(settings, "DATABASE_URL", None)),
        flush=True,
    )

    # 2. Se não houver URL completa, tenta montar a partir das variáveis individuais do MySQL
    if not url:
        host = _clean_env(os.getenv("MYSQLHOST")) or _clean_env(getattr(settings, "MYSQLHOST", None))
        port = _clean_env(os.getenv("MYSQLPORT")) or _clean_env(getattr(settings, "MYSQLPORT", None)) or "3306"
        user = _clean_env(os.getenv("MYSQLUSER")) or _clean_env(getattr(settings, "MYSQLUSER", None))
        password = _clean_env(os.getenv("MYSQLPASSWORD")) or _clean_env(getattr(settings, "MYSQLPASSWORD", None))
        database = _clean_env(os.getenv("MYSQLDATABASE")) or _clean_env(getattr(settings, "MYSQLDATABASE", None))

        if host and user and password and database:
            url = f"mysql://{user}:{quote_plus(password)}@{host}:{port}/{database}"

    # 3. Fallback para settings.DATABASE_URL (ex.: sqlite:///./undersound.db ou .env local)
    if not url:
        url = _clean_env(getattr(settings, "DATABASE_URL", None))

    if not url:
        raise ValueError(
            "DATABASE_URL não configurada e variáveis do MySQL não encontradas."
        )

    # 4. Ajusta o esquema para usar o driver PyMySQL no SQLAlchemy
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