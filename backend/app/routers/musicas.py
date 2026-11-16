import os
import shutil
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Form, Header, Response
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from typing import List
from app.database import get_db
from app import models, schemas, security
from app.external_services import buscar_artista_musicbrainz
from app.logger import logger
from app.models import Album, Musica

router = APIRouter(prefix="/api/albuns", tags=["Álbuns e Músicas"])

# Diretório para armazenamento local dos arquivos de áudio
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
DIRETORIO_UPLOADS = "uploads/capas"
os.makedirs(DIRETORIO_UPLOADS, exist_ok=True)


@router.post("/", response_model=schemas.AlbumResponse, status_code=status.HTTP_201_CREATED)
def criar_album(
    titulo: str = Form(...),
    ano: int = Form(...),
    genero: str = Form(...),
    file: UploadFile = File(None), # Arquivo de capa opcional enviado do computador
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    # Restringir publicação estritamente ao perfil Artista/Banda
    if usuario_atual.tipo_usuario != "artista":
        logger.warning(f"ACESSO NEGADO: Usuário ID={usuario_atual.id} (Ouvinte) tentou criar um álbum.")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas usuários com perfil de Artista/Banda podem publicar álbuns e músicas."
        )

    capa_url = None
    if file:
        caminho_arquivo = os.path.join(DIRETORIO_UPLOADS, file.filename)
        with open(caminho_arquivo, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        capa_url = f"/uploads/capas/{file.filename}"

    novo_album = models.Album(
        titulo=titulo,
        ano=ano,
        genero=genero,
        capa_url=capa_url,
        artista_id=usuario_atual.id
    )
    db.add(novo_album)
    db.commit()
    db.refresh(novo_album)
    
    logger.info(f"ÁLBUM CRIADO: ID={novo_album.id}, Título='{novo_album.titulo}' pelo Artista ID={usuario_atual.id}")
    return novo_album

@router.delete("/{album_id}", status_code=204)
def excluir_album(
    album_id: int, 
    db: Session = Depends(get_db), 
    usuario_atual = Depends(security.obter_usuario_atual)
):
    album = db.query(Album).filter(Album.id == album_id).first()
    if not album:
        raise HTTPException(status_code=404, detail="Álbum não encontrado.")

    db.delete(album)
    db.commit()
    return Response(status_code=204)

@router.delete("/musicas/{musica_id}", status_code=204)
def excluir_musica(
    musica_id: int, 
    db: Session = Depends(get_db), 
    usuario_atual = Depends(security.obter_usuario_atual)
):
    musica = db.query(Musica).filter(Musica.id == musica_id).first()
    if not musica:
        raise HTTPException(status_code=404, detail="Música não encontrada.")

    db.delete(musica)
    db.commit()
    return Response(status_code=204)


@router.get("/", response_model=List[schemas.AlbumResponse])
def listar_albuns(db: Session = Depends(get_db)):
    albuns = db.query(models.Album).all()
    
    # MPreenche o artista_nome para cada álbum antes de retornar
    resultado = []
    for album in albuns:
        album_dict = {
            "id": album.id,
            "titulo": album.titulo,
            "ano": album.ano,
            "genero": album.genero,
            "capa_url": album.capa_url,
            "artista_id": album.artista_id,
            "artista_nome": album.artista.nome if album.artista else "Desconhecido",
            "musicas": album.musicas
        }
        resultado.append(album_dict)
        
    return resultado


@router.post("/{album_id}/musicas", response_model=schemas.MusicaResponse, status_code=status.HTTP_201_CREATED)
def adicionar_musica(
    album_id: int,
    musica: schemas.MusicaCreate,
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    # Validar se o usuário é artista
    if usuario_atual.tipo_usuario != "artista":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Apenas artistas podem adicionar músicas."
        )

    album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if not album:
        raise HTTPException(status_code=404, detail="Álbum não encontrado.")

    if album.artista_id != usuario_atual.id:
        logger.warning(f"ACESSO NEGADO: Artista ID={usuario_atual.id} tentou alterar Álbum ID={album_id}")
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

@router.patch("/musicas/{musica_id}/ordem", status_code=200)
def atualizar_ordem_musica(
    musica_id: int,
    nova_ordem: int = Form(...),
    db: Session = Depends(get_db),
    usuario_atual = Depends(security.obter_usuario_atual)
):
    # Valida se o usuário é artista
    if usuario_atual.tipo_usuario != "artista":
        raise HTTPException(status_code=403, detail="Apenas artistas podem alterar a ordem das músicas.")

    musica = db.query(Musica).filter(Musica.id == musica_id).first()
    if not musica:
        raise HTTPException(status_code=404, detail="Música não encontrada.")
    
    # Verifica se o álbum pertence ao artista logado
    if musica.album.artista_id != usuario_atual.id:
        raise HTTPException(status_code=403, detail="Você não tem permissão para alterar este álbum.")

    musica.ordem = nova_ordem
    db.commit()
    return {"mensagem": "Ordem atualizada com sucesso!"}

@router.put("/{album_id}", response_model=schemas.AlbumResponse)
async def atualizar_album(
    album_id: int,
    titulo: str = Form(...),
    ano: int = Form(...),
    genero: str = Form(...),
    file: UploadFile = File(None),
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    if usuario_atual.tipo_usuario != "artista":
        raise HTTPException(status_code=403, detail="Apenas artistas podem editar álbuns.")

    album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if not album or album.artista_id != usuario_atual.id:
        raise HTTPException(status_code=404, detail="Álbum não encontrado ou sem permissão.")

    album.titulo = titulo
    album.ano = ano
    album.genero = genero

    if file:
        if not file.filename.lower().endswith(('.jpg', '.jpeg', '.png', '.webp')):
            raise HTTPException(status_code=400, detail="Formato de imagem inválido.")
        
        caminho_arquivo = os.path.join(DIRETORIO_UPLOADS, file.filename)
        with open(caminho_arquivo, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        album.capa_url = f"/uploads/capas/{file.filename}"

    db.commit()
    db.refresh(album)
    
    logger.info(f"ÁLBUM ATUALIZADO: ID={album.id}, Título='{album.titulo}'")
    return album

# NOVO ENDPOINT DE UPLOAD DE ÁUDIO (Com suporte a .mpeg e .mpg)
@router.post("/{album_id}/upload-audio", status_code=status.HTTP_201_CREATED)
async def upload_arquivo_musica(
    album_id: int,
    titulo: str = Form(...),
    duracao_segundos: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)
):
    if usuario_atual.tipo_usuario != "artista":
        raise HTTPException(status_code=403, detail="Apenas artistas podem enviar arquivos de áudio.")

    album = db.query(models.Album).filter(models.Album.id == album_id).first()
    if not album or album.artista_id != usuario_atual.id:
        raise HTTPException(status_code=404, detail="Álbum não encontrado ou sem permissão.")

    # Validação atualizada para aceitar .mpeg e .mpg além de mp3, wav e ogg
    if not file.filename.lower().endswith(('.mp3', '.wav', '.ogg', '.mpeg', '.mpg')):
        raise HTTPException(status_code=400, detail="Formato de arquivo de áudio inválido.")

    # Salva o arquivo fisicamente na pasta uploads
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    # URL gerada para consumo do motor de streaming do próprio backend
    arquivo_url = f"http://localhost:8000/api/albuns/stream/{file.filename}"

    nova_musica = models.Musica(
        titulo=titulo,
        duracao_segundos=duracao_segundos,
        arquivo_url=arquivo_url,
        album_id=album_id
    )
    db.add(nova_musica)
    db.commit()
    db.refresh(nova_musica)
    
    logger.info(f"UPLOAD DE ÁUDIO REALIZADO: '{file.filename}' para o Álbum ID={album_id}")
    return {"mensagem": "Upload efetuado com sucesso", "arquivo_url": arquivo_url}


# ENDPOINT DE STREAMING COM SUPORTE A HTTP RANGE
@router.get("/stream/{filename}")
async def stream_audio(filename: str, range: str = Header(None)):
    file_path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Arquivo de áudio não encontrado.")
    
    file_size = os.path.getsize(file_path)
    start = 0
    end = file_size - 1
    
    if range:
        range_str = range.replace("bytes=", "")
        parts = range_str.split("-")
        start = int(parts[0])
        if parts[1]:
            end = int(parts[1])
            
    chunk_size = (end - start) + 1
    
    def iterfile():
        with open(file_path, "rb") as f:
            f.seek(start)
            remaining = chunk_size
            while remaining > 0:
                chunk_to_read = min(65536, remaining)
                data = f.read(chunk_to_read)
                if not data:
                    break
                remaining -= len(data)
                yield data

    headers = {
        "Content-Range": f"bytes {start}-{end}/{file_size}",
        "Accept-Ranges": "bytes",
        "Content-Length": str(chunk_size),
        "Content-Type": "audio/mpeg",
    }
    return StreamingResponse(iterfile(), status_code=206, headers=headers)

@router.get("/consulta-externa/{nome_artista}")
async def consultar_artista_externo(nome_artista: str):
    return await buscar_artista_musicbrainz(nome_artista)