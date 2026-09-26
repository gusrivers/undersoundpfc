from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base
from app.routers import auth, musicas
from app.logger import logger

# Criação automática das tabelas no Banco de Dados
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Undersound API",
    description="Backend para plataforma de streaming e gestão musical underground - Entrega 2",
    version="1.0.0"
)

# Configuração de CORS (Autorizando requisições do Vite em Localhost e Vercel)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite chamadas de qualquer origem no desenvolvimento
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