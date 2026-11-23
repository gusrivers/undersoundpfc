from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import auth, musicas
from app.logger import logger
import os
from fastapi.staticfiles import StaticFiles

# Criação automática das tabelas no Banco de Dados
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Undersound API",
    description="Backend para plataforma de streaming e gestão musical underground - Entrega 2",
    version="1.0.0"
)

os.makedirs("uploads", exist_ok=True)
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

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
    return {"status": "Online", "projeto": "Undersound", "versao": "Entrega 2 (28/09/2026)"}