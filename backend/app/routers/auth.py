from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.database import get_db
from app import models, schemas, security
from app.logger import logger

router = APIRouter(prefix="/api/auth", tags=["Autenticação & LGPD"])

@router.post("/cadastro", response_model=schemas.UsuarioResponse, status_code=status.HTTP_201_CREATED)
def cadastrar_usuario(usuario: schemas.UsuarioCreate, db: Session = Depends(get_db)):
    if not usuario.aceitou_termos_lgpd:
        logger.warning(f"Tentativa de cadastro sem aceite da LGPD pelo email: {usuario.email}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="É obrigatório aceitar os Termos de Uso e a Política de Privacidade (LGPD)."
        )

    db_usuario = db.query(models.Usuario).filter(models.Usuario.email == usuario.email).first()
    if db_usuario:
        raise HTTPException(status_code=400, detail="E-mail já cadastrado no sistema.")

    novo_usuario = models.Usuario(
        nome=usuario.nome,
        email=usuario.email,
        senha_hash=security.obter_hash_senha(usuario.senha),
        tipo_usuario=usuario.tipo_usuario,
        aceitou_termos_lgpd=usuario.aceitou_termos_lgpd
    )
    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)

    logger.info(f"NOVO USUÁRIO CADASTRADO: ID={novo_usuario.id}, Email={novo_usuario.email}, Tipo={novo_usuario.tipo_usuario}")
    return novo_usuario

@router.post("/login", response_model=schemas.Token)
def login(login_data: schemas.LoginData, db: Session = Depends(get_db)):
    usuario = db.query(models.Usuario).filter(models.Usuario.email == login_data.email).first()
    
    if not usuario or not security.verificar_senha(login_data.senha, usuario.senha_hash):
        logger.warning(f"FALHA DE AUTENTICAÇÃO: Tentativa incorreta de login para o email: {login_data.email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-mail ou senha incorretos."
        )

    access_token = security.criar_access_token(data={"sub": usuario.email, "tipo": usuario.tipo_usuario})
    logger.info(f"LOGIN BEM-SUCEDIDO: Email={usuario.email}")
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me", response_model=schemas.UsuarioResponse)
def obter_perfil_logado(usuario_atual: models.Usuario = Depends(security.obter_usuario_atual)):
    return usuario_atual