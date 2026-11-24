from unittest.mock import AsyncMock, patch
from app import schemas
from app.routers import musicas


def _registrar_e_logar(client, nome, email, tipo_usuario):
    client.post(
        "/api/auth/cadastro",
        json={
            "nome": nome,
            "email": email,
            "senha": "Senha123",
            "tipo_usuario": tipo_usuario,
            "aceitou_termos_lgpd": True,
        },
    )
    token = client.post(
        "/api/auth/login",
        json={"email": email, "senha": "Senha123"},
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_schema_album_response_aceita_artista_id_nulo():
    album = schemas.AlbumResponse(
        id=1,
        titulo="Demo Sem Artista",
        ano=2026,
        genero="Pós-Punk",
        capa_url=None,
        artista_id=None,
        artista_nome="Artista Removido",
        musicas=[],
    )
    assert album.artista_id is None
    assert album.musicas == []


def test_ouvinte_nao_pode_criar_album_e_artista_pode(client):
    headers_ouvinte = _registrar_e_logar(
        client, "Ouvinte", "ouvinte.album@exemplo.com", "ouvinte"
    )
    resp_bloqueado = client.post(
        "/api/albuns/",
        data={"titulo": "EP Proibido", "ano": "2026", "genero": "Indie"},
        headers=headers_ouvinte,
    )
    assert resp_bloqueado.status_code == 403

    headers_artista = _registrar_e_logar(
        client, "Artista Autor", "artista.album@exemplo.com", "artista"
    )
    resp_criado = client.post(
        "/api/albuns/",
        data={"titulo": "Sessao Noturna", "ano": "2026", "genero": "Shoelace / Rock"},
        headers=headers_artista,
    )
    assert resp_criado.status_code in (200, 201)

    lista = client.get("/api/albuns/")
    assert lista.status_code == 200
    assert len(lista.json()) >= 1


def test_consulta_externa_musicbrainz_mockada(client):
    resposta_simulada = {"artistas": [{"nome": "Banda Autoral Mock", "pais": "BR"}]}
    with patch.object(
        musicas,
        "buscar_artista_musicbrainz",
        new=AsyncMock(return_value=resposta_simulada),
    ):
        resp = client.get("/api/albuns/consulta-externa/Banda%20Autoral%20Mock")
        assert resp.status_code == 200
        assert resp.json() == resposta_simulada