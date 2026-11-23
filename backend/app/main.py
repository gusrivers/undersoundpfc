from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.database import engine, Base
from app.routers import auth, musicas
from app.logger import logger
import os

# Criação automática das tabelas no Banco de Dados
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Undersound API",
    description="Backend para plataforma de streaming e gestão musical underground - Entrega 2",
    version="1.0.0"
)

# Diretório único e padronizado de uploads (raiz do backend)
BASE_UPLOADS_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "uploads")
)
os.makedirs(BASE_UPLOADS_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE_UPLOADS_DIR, "capas"), exist_ok=True)

app.mount("/uploads", StaticFiles(directory=BASE_UPLOADS_DIR), name="uploads")

# Configuração de CORS
origins = [
    "https://undersoundpfc-front.onrender.com",
    "http://localhost:5173",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Registro das Rotas
app.include_router(auth.router)
app.include_router(musicas.router)


@app.get("/")
def home():
    logger.info("Acesso à rota principal da API.")
    return {"status": "Online", "projeto": "Undersound", "versao": "Entrega 2"}