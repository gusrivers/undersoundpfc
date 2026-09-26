from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

# Autenticação e Usuário
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str
    tipo_usuario: Optional[str] = "ouvinte"
    aceitou_termos_lgpd: bool  # Obrigatório para conformidade LGPD

class UsuarioResponse(BaseModel):
    id: int
    nome: str
    email: EmailStr
    tipo_usuario: str
    aceitou_termos_lgpd: bool
    data_aceite_lgpd: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class LoginData(BaseModel):
    email: EmailStr
    senha: str

# Músicas e Álbuns
class MusicaCreate(BaseModel):
    titulo: str
    duracao_segundos: int
    arquivo_url: str

class MusicaResponse(MusicaCreate):
    id: int
    album_id: int

    class Config:
        from_attributes = True

class AlbumCreate(BaseModel):
    titulo: str
    ano: int
    genero: str
    capa_url: Optional[str] = None

class AlbumResponse(AlbumCreate):
    id: int
    artista_id: int
    musicas: List[MusicaResponse] = []

    class Config:
        from_attributes = True