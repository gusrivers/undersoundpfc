from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app import models, schemas, security
from app.external_services import buscar_artista_musicbrainz
from app.logger import logger

router = APIRouter(prefix="/api/albuns", tags=["Álbuns e Músicas"])

@router.post("/", response_model=schemas.AlbumResponse, status_code=status.HTTP_201_CREATED)
def criar_album(
    album: schemas.AlbumCreate,
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    novo_album = models.Album(
        titulo=album.titulo,
        ano=album.ano,
        genero=album.genero,
        capa_url=album.capa_url,
        artista_id=usuario_atual.id
    )
    db.add(novo_album)
    db.commit()
    db.refresh(novo_album)
    logger.info(f"ÁLBUM CRIADO: ID={novo_album.id}, Título='{novo_album.titulo}' pelo Usuário ID={usuario_atual.id}")
    return novo_album

@router.get("/", response_model=List[schemas.AlbumResponse])
def listar_albuns(db: Session = Depends(get_db)):
    return db.query(models.Album).all()

@router.post("/{album_id}/musicas", response_model=schemas.MusicaResponse, status_code=status.HTTP_201_CREATED)
def adicionar_musica(
    album_id: int,
    musica: schemas.MusicaCreate,
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if not album:
        raise HTTPException(status_code=404, detail="Álbum não encontrado.")

    if album.artista_id != usuario_atual.id:
        logger.warning(f"ACESSO NEGADO: Usuário ID={usuario_atual.id} tentou adicionar música ao Álbum ID={album_id}")
        raise HTTPException(status_code=403, detail="Você não tem permissão para alterar este álbum.")

    nova_musica = models.Musica(
        titulo=musica.titulo,
        duracao_segundos=musica.duracao_segundos,
        arquivo_url=musica.arquivo_url,
        album_id=album_id
    )
    db.add(nova_musica)
    db.commit()
    db.refresh(nova_musica)
    logger.info(f"MÚSICA ADICIONADA: ID={nova_musica.id}, Título='{nova_musica.titulo}' ao Álbum ID={album_id}")
    return nova_musica

# Endpoint de Integração Externa
@router.get("/consulta-externa/{nome_artista}")
async def consultar_artista_externo(nome_artista: str):
    return await buscar_artista_musicbrainz(nome_artista)