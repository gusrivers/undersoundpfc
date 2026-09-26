from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database import Base

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String(100), nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    tipo_usuario = Column(String(20), default="ouvinte") # 'ouvinte' ou 'artista'
    
    # Requisito LGPD: Registro de aceite dos termos
    aceitou_termos_lgpd = Column(Boolean, default=False, nullable=False)
    data_aceite_lgpd = Column(DateTime, default=datetime.utcnow)

    albuns = relationship("Album", back_populates="artista")

class Album(Base):
    __tablename__ = "albuns"

    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String(150), nullable=False)
    ano = Column(Integer, nullable=False)
    genero = Column(String(50), nullable=False)
    capa_url = Column(String(255), nullable=True)
    artista_id = Column(Integer, ForeignKey("usuarios.id"))

    artista = relationship("Usuario", back_populates="albuns")
    musicas = relationship("Musica", back_populates="album")

class Musica(Base):
    __tablename__ = "musicas"

    id = Column(Integer, primary_key=True, index=True)
    titulo = Column(String(150), nullable=False)
    duracao_segundos = Column(Integer, nullable=False, default=180)
    arquivo_url = Column(String(255), nullable=False)
    album_id = Column(Integer, ForeignKey("albuns.id"))

    album = relationship("Album", back_populates="musicas")