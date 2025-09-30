from fastapi import FastAPI, HTTPException, Depends, status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlmodel import SQLModel, Field, Session, select, create_engine, Relationship
from typing import List, Optional, Annotated
from datetime import datetime, timedelta
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
import os
import shutil 

# Configuração do MySQL
DATABASE_URL = "mysql+pymysql://root:@localhost/undersound"
engine = create_engine(DATABASE_URL, echo=True)

# Configurações de segurança JWT
SECRET_KEY = "testeapipfc"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Diretório para salvar as músicas (ainda em testes)
UPLOAD_DIR = "uploads/musics"
os.makedirs(UPLOAD_DIR, exist_ok=True) 

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Inicialização da aplicação FastAPI
app = FastAPI(title="Streaming Musical API", description="API com MySQL e Users para PFC")

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: str = Field(index=True, unique=True)
    hashed_password: str
    full_name: Optional[str] = None
    is_active: bool = Field(default=True)
    deleted_at: Optional[datetime] = Field(default=None) 
    created_at: datetime = Field(default_factory=datetime.now)
    
    playlists: List["Playlist"] = Relationship(back_populates="owner")

class Artist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    genre: str
    musics: List["Music"] = Relationship(back_populates="artist")

class Music(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(index=True)
    duration: int
    album: Optional[str] = None
    artist_id: int = Field(foreign_key="artist.id")
    file_path: Optional[str] = None 
    
    artist: Artist = Relationship(back_populates="musics")
    playlists: List["PlaylistMusic"] = Relationship(back_populates="music")

class Playlist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    is_public: bool = Field(default=True)
    owner_id: int = Field(foreign_key="user.id")
    
    owner: User = Relationship(back_populates="playlists")
    musics: List["PlaylistMusic"] = Relationship(back_populates="playlist")

class PlaylistMusic(SQLModel, table=True):
    playlist_id: int = Field(foreign_key="playlist.id", primary_key=True)
    music_id: int = Field(foreign_key="music.id", primary_key=True)
    added_at: datetime = Field(default_factory=datetime.now)
    
    playlist: Playlist = Relationship(back_populates="musics")
    music: Music = Relationship(back_populates="playlists")

class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    full_name: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool
    created_at: datetime

class UserUpdate(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    password: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None
    is_active: Optional[bool] = None 

class ArtistCreate(BaseModel):
    name: str
    genre: str

class ArtistResponse(BaseModel):
    id: int
    name: str
    genre: str

class MusicCreate(BaseModel):
    title: str
    duration: int
    album: Optional[str] = None
    artist_id: int

class MusicResponse(SQLModel):
    id: int
    title: str
    duration: int
    album: Optional[str] = None
    file_path: Optional[str] = None 
    artist: ArtistResponse 

class PlaylistCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_public: bool = True

class PlaylistResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    created_at: datetime
    is_public: bool

def get_user_by_username(session: Session, username: str) -> Optional[User]:
    return session.exec(select(User).where(User.username == username)).first()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user_by_email(session: Session, email: str):
    return session.exec(select(User).where(User.email == email)).first()

def authenticate_user(session: Session, username: str, password: str):
    user = get_user_by_username(session, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    return user

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)], 
    session: Session = Depends(get_session)
):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        is_active: bool = payload.get("is_active")
        if username is None or is_active is None:
            raise credentials_exception
        token_data = TokenData(username=username, is_active=is_active)
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(session, username=token_data.username)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user account")
        
    return user

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

@app.post("/token", response_model=Token)
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: Session = Depends(get_session)
):
    user = authenticate_user(session, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password or account deactivated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username, "is_active": user.is_active})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/register", response_model=UserResponse)
def register_user(user: UserCreate, session: Session = Depends(get_session)):
    if get_user_by_username(session, user.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    if get_user_by_email(session, user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        full_name=user.full_name,
    )
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: Annotated[User, Depends(get_current_active_user)]):
    return current_user

@app.put("/users/me", response_model=UserResponse)
async def update_user_me(
    user_update: UserUpdate,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Session = Depends(get_session)
):
    update_data = user_update.dict(exclude_unset=True)
    
    if "password" in update_data:
        update_data["hashed_password"] = get_password_hash(update_data.pop("password"))
    
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    session.add(current_user)
    session.commit()
    session.refresh(current_user)
    return current_user

@app.delete("/users/me/delete", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account_lgpd(
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Session = Depends(get_session)
):
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Account already deactivated.")
        
    current_user.is_active = False
    current_user.deleted_at = datetime.now() 
    
    session.add(current_user)
    session.commit()
    return {"message": "Account successfully deactivated (Soft Delete) for LGPD compliance."}

@app.post("/artists/", response_model=ArtistResponse)
def create_artist(artist: ArtistCreate, session: Session = Depends(get_session)):
    db_artist = Artist(**artist.dict())
    session.add(db_artist)
    session.commit()
    session.refresh(db_artist)
    return db_artist

@app.get("/artists/", response_model=List[ArtistResponse])
def read_artists(session: Session = Depends(get_session)):
    artists = session.exec(select(Artist)).all()
    return artists

@app.get("/artists/{artist_id}", response_model=ArtistResponse)
def read_artist(artist_id: int, session: Session = Depends(get_session)):
    artist = session.get(Artist, artist_id)
    if not artist:
        raise HTTPException(status_code=404, detail="Artista não encontrado")
    return artist

# Rotas do upload e streaming de música

@app.post("/upload-music", response_model=MusicResponse)
async def upload_music(
    file: Annotated[UploadFile, File()], 
    title: str,
    duration: int,
    artist_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)], 
    session: Session = Depends(get_session),
    album: Optional[str] = None
):
    if file.content_type not in ["audio/mpeg", "audio/wav"]:
        raise HTTPException(status_code=400, detail="Tipo de arquivo não suportado. Use MP3 ou WAV.")
    
    artist = session.get(Artist, artist_id)
    if not artist:
        raise HTTPException(status_code=404, detail="Artista não encontrado")
    file_extension = file.filename.split(".")[-1]
    safe_filename = f"{artist_id}_{title.replace(' ', '_')}_{datetime.now().timestamp()}.{file_extension}"
    file_location = os.path.join(UPLOAD_DIR, safe_filename)
    
    try:
        with open(file_location, "wb") as f:
            shutil.copyfileobj(file.file, f)
    except Exception as e:
        print(f"Erro ao salvar arquivo: {e}")
        raise HTTPException(status_code=500, detail="Falha ao salvar o arquivo de música.")
    finally:
        await file.close() 
    db_music = Music(
        title=title,
        duration=duration,
        album=album,
        artist_id=artist_id,
        file_path=file_location 
    )
    
    session.add(db_music)
    session.commit()
    session.refresh(db_music)
    return db_music

@app.get("/stream-music/{music_id}")
async def stream_music(music_id: int, session: Session = Depends(get_session)):
    music = session.get(Music, music_id)
    
    if not music or not music.file_path or not os.path.exists(music.file_path):
        raise HTTPException(status_code=404, detail="Música ou arquivo não encontrado.")

    media_type = "audio/mpeg" if music.file_path.lower().endswith(".mp3") else "audio/wav"
    
    return FileResponse(
        music.file_path, 
        media_type=media_type, 
        filename=os.path.basename(music.file_path)
    )

@app.get("/musics/", response_model=List[MusicResponse])
def read_musics(session: Session = Depends(get_session)):
    statement = select(Music)
    musics = session.exec(statement).all()
    return musics

@app.get("/musics/{music_id}", response_model=MusicResponse)
def read_music(music_id: int, session: Session = Depends(get_session)):
    music = session.get(Music, music_id)
    if not music:
        raise HTTPException(status_code=404, detail="Música não encontrada")
    return music

@app.put("/musics/{music_id}", response_model=MusicResponse)
def update_music(music_id: int, music_update: MusicCreate, session: Session = Depends(get_session)):
    db_music = session.get(Music, music_id)
    if not db_music:
        raise HTTPException(status_code=404, detail="Música não encontrada")

    if music_update.artist_id != db_music.artist_id:
        artist = session.get(Artist, music_update.artist_id)
        if not artist:
            raise HTTPException(status_code=404, detail="Artista não encontrado")

    for key, value in music_update.dict().items():
        setattr(db_music, key, value)
    
    session.add(db_music)
    session.commit()
    session.refresh(db_music)
    return db_music

@app.delete("/musics/{music_id}")
def delete_music(music_id: int, session: Session = Depends(get_session)):
    music = session.get(Music, music_id)
    if not music:
        raise HTTPException(status_code=404, detail="Música não encontrada")
    
    session.delete(music)
    session.commit()
    return {"message": "Música deletada com sucesso"}

@app.post("/playlists/", response_model=PlaylistResponse)
def create_playlist(
    playlist: PlaylistCreate,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Session = Depends(get_session)
):
    db_playlist = Playlist(**playlist.dict(), owner_id=current_user.id)
    session.add(db_playlist)
    session.commit()
    session.refresh(db_playlist)
    return db_playlist

@app.get("/playlists/", response_model=List[PlaylistResponse])
def read_playlists(session: Session = Depends(get_session)):
    playlists = session.exec(select(Playlist)).all()
    return playlists

@app.get("/playlists/{playlist_id}", response_model=PlaylistResponse)
def read_playlist(playlist_id: int, session: Session = Depends(get_session)):
    playlist = session.get(Playlist, playlist_id)
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist não encontrada")
    return playlist

@app.post("/playlists/{playlist_id}/musics/{music_id}")
def add_music_to_playlist(
    playlist_id: int,
    music_id: int,
    current_user: Annotated[User, Depends(get_current_active_user)],
    session: Session = Depends(get_session)
):
    playlist = session.get(Playlist, playlist_id)
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist não encontrada")
    
    if playlist.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    music = session.get(Music, music_id)
    if not music:
        raise HTTPException(status_code=404, detail="Música não encontrada")
    
    existing_link = session.exec(
        select(PlaylistMusic)
        .where(PlaylistMusic.playlist_id == playlist_id)
        .where(PlaylistMusic.music_id == music_id)
    ).first()
    
    if existing_link:
        raise HTTPException(status_code=400, detail="Música já está na playlist")
    
    playlist_music = PlaylistMusic(playlist_id=playlist_id, music_id=music_id)
    session.add(playlist_music)
    session.commit()
    
    return {"message": "Música adicionada à playlist com sucesso"}

@app.get("/playlists/{playlist_id}/musics", response_model=List[MusicResponse])
def get_playlist_musics(playlist_id: int, session: Session = Depends(get_session)):
    playlist = session.get(Playlist, playlist_id)
    if not playlist:
        raise HTTPException(status_code=404, detail="Playlist não encontrada")
    
    statement = (
        select(Music)
        .join(PlaylistMusic)
        .where(PlaylistMusic.playlist_id == playlist_id)
    )
    musics = session.exec(statement).all()
    
    return musics

FRONTEND_DIST_DIR = "frontend/dist"

app.mount(
    "/",
    StaticFiles(directory=FRONTEND_DIST_DIR, html=True), 
    name="static"
)

@app.on_event("startup")
def on_startup():
    create_db_and_tables()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
