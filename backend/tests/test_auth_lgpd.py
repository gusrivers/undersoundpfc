from app.routers import auth


def test_cadastro_bloqueia_sem_aceite_lgpd(client):
    payload = {
        "nome": "Artista Teste",
        "email": "artista.sem.lgpd@exemplo.com",
        "senha": "SenhaForte123",
        "tipo_usuario": "artista",
        "aceitou_termos_lgpd": False,
    }
    resp = client.post("/api/auth/cadastro", json=payload)
    assert resp.status_code == 400
    assert "LGPD" in resp.json()["detail"]


def test_cadastro_login_e_bloqueio_email_duplicado(client):
    payload = {
        "nome": "Banda Garagem",
        "email": "banda.garagem@exemplo.com",
        "senha": "SenhaForte123",
        "tipo_usuario": "artista",
        "aceitou_termos_lgpd": True,
    }
    resp_cad = client.post("/api/auth/cadastro", json=payload)
    assert resp_cad.status_code == 201
    assert resp_cad.json()["email"] == "banda.garagem@exemplo.com"

    # E-mail duplicado deve falhar
    resp_dup = client.post("/api/auth/cadastro", json=payload)
    assert resp_dup.status_code == 400

    # Login com senha incorreta deve retornar 401
    resp_err = client.post(
        "/api/auth/login",
        json={"email": "banda.garagem@exemplo.com", "senha": "SenhaErrada"},
    )
    assert resp_err.status_code == 401

    # Login válido deve retornar token JWT
    resp_ok = client.post(
        "/api/auth/login",
        json={"email": "banda.garagem@exemplo.com", "senha": "SenhaForte123"},
    )
    assert resp_ok.status_code == 200
    assert "access_token" in resp_ok.json()


def test_recuperacao_e_redefinicao_de_senha(client):
    auth.TOKENS_RECUPERACAO.clear()
    client.post(
        "/api/auth/cadastro",
        json={
            "nome": "Ouvinte Teste",
            "email": "ouvinte.teste@exemplo.com",
            "senha": "SenhaAntiga123",
            "tipo_usuario": "ouvinte",
            "aceitou_termos_lgpd": True,
        },
    )

    resp_esq = client.post(
        "/api/auth/esqueci-senha",
        json={"email": "ouvinte.teste@exemplo.com"},
    )
    assert resp_esq.status_code == 200
    token = resp_esq.json().get("token_teste")
    assert token

    resp_red = client.post(
        "/api/auth/redefinir-senha",
        json={"token": token, "nova_senha": "NovaSenha456"},
    )
    assert resp_red.status_code == 200

    # Senha antiga não entra mais
    login_antigo = client.post(
        "/api/auth/login",
        json={"email": "ouvinte.teste@exemplo.com", "senha": "SenhaAntiga123"},
    )
    assert login_antigo.status_code == 401

    # Nova senha entra com sucesso
    login_novo = client.post(
        "/api/auth/login",
        json={"email": "ouvinte.teste@exemplo.com", "senha": "NovaSenha456"},
    )
    assert login_novo.status_code == 200


def test_exclusao_de_conta_rf06(client):
    client.post(
        "/api/auth/cadastro",
        json={
            "nome": "Conta Para Excluir",
            "email": "excluir@exemplo.com",
            "senha": "Senha123",
            "tipo_usuario": "ouvinte",
            "aceitou_termos_lgpd": True,
        },
    )
    token = client.post(
        "/api/auth/login",
        json={"email": "excluir@exemplo.com", "senha": "Senha123"},
    ).json()["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    resp_del = client.delete("/api/auth/conta/excluir", headers=headers)
    assert resp_del.status_code == 200

    # Após excluir, login deve falhar
    resp_login = client.post(
        "/api/auth/login",
        json={"email": "excluir@exemplo.com", "senha": "Senha123"},
    )
    assert resp_login.status_code == 401