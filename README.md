Undersound — Plataforma de Streaming e Divulgação Musical Independente

O **Undersound** é uma plataforma web *full-stack* desenvolvida como Projeto de Final de Curso (PFC) no Bacharelado em Engenharia de Software da **Universidade de Mogi das Cruzes (UMC)**. O sistema tem como propósito democratizar e centralizar a divulgação da cena musical independente e underground, oferecendo um ambiente gratuito para que artistas gerenciem e distribuam seus acervos autorais sem depender de algoritmos comerciais ou taxas abusivas.

---

Visão Geral e Personas

A arquitetura da plataforma foi projetada para atender a dois perfis distintos de usuários:

- **Artista / Banda Independente:** Criadores emergentes que necessitam de uma ferramenta simplificada para cadastrar álbuns, fazer upload real de arquivos de áudio e acompanhar o desempenho do catálogo através de um dashboard gerencial.
- **Ouvinte / Apoiador da Cena Local:** Entusiastas de subgêneros alternativos que buscam descoberta musical centralizada, consulta de metadados globais e reprodução contínua sem interrupções.

---

Requisitos Implementados

### Requisitos Funcionais (RF)
- **[RF01] Autenticação e Controle de Perfis:** Cadastro e login com diferenciação de papéis (*Ouvinte/Fã* e *Artista/Banda Independente*), restringindo rotas de publicação exclusivamente aos artistas autenticados via tokens **JWT** e senhas criptografadas com **bcrypt**.
- **[RF02] Conformidade LGPD e Termos de Uso:** Bloqueio cadastral caso o usuário não aceite explicitamente os Termos de Uso e a Política de Privacidade.
- **[RF03] Gestão de Álbuns e Upload de Mídia:** Criação de álbuns (título, ano, gênero, capa) e upload real de arquivos de áudio binários (`.mp3`, `.wav`) gerenciados pelo servidor.
- **[RF04] Reprodução Contínua (SPA):** Player de áudio fixo no rodapé que mantém a execução ininterrupta enquanto o usuário navega pelas páginas da aplicação.
- **[RF05] Consulta Externa (MusicBrainz):** Integração assíncrona com a API pública do **MusicBrainz** (`ws/2`) para busca de metadados internacionais, equipada com mecanismo de contingência (*fallback*) no back-end.
- **[RF06] Direitos do Titular (LGPD):** Fluxo completo de solicitação e execução de exclusão definitiva de conta (*Direito ao Esquecimento*), removendo os dados pessoais e publicações vinculadas.
- **Dashboard Gerencial:** Painel analítico exclusivo para artistas acompanharem os indicadores consolidados do catálogo e das publicações.

### Requisitos Não Funcionais (RNF)
- **[RNF01] Desempenho e Concorrência:** Processamento assíncrono (`async/await`) e leitura otimizada de arquivos de mídia por blocos (`aiofiles`) no FastAPI.
- **[RNF02] Segurança da Informação:** Armazenamento exclusivo de senhas em hash **bcrypt**, comunicação stateless via **JWT** com expiração configurável e proteção de variáveis sensíveis fora do versionamento.
- **[RNF03] Privacidade e Auditoria:** Rastreabilidade de eventos críticos de acesso, falhas de autenticação e cadastros através do arquivo `auditoria.log`.
- **[RNF04] Portabilidade e Manutenibilidade:** Desacoplamento da camada de persistência mediado pelo ORM **SQLAlchemy**.

---

Stack Tecnológica e Arquitetura

O sistema segue uma arquitetura desacoplada em três camadas (Apresentação, Aplicação e Persistência/Serviços):

### **Front-end (Camada de Apresentação)**
- **React 18** + **TypeScript** + **Vite.js**
- **Axios** (com interceptors para envio automático de tokens JWT)
- **Lucide React** para iconografia e modais customizados
- **HTML5 Audio Player** integrado ao estado global da SPA

### **Back-end (Camada de Aplicação)**
- **Python 3.11+** com **FastAPI**
- **SQLAlchemy** (ORM) e **Pydantic** (validação de esquemas e DTOs)
- **Passlib (bcrypt)** e **Python-JOSE (JWT)** para autenticação e criptografia
- **HTTPX** e **Aiofiles** para requisições assíncronas e streaming de áudio

### **Banco de Dados e Serviços Externos**
- **MySQL 8.0** (gerenciado via phpMyAdmin/XAMPP)
- **MusicBrainz API (`ws/2`)** para enriquecimento cultural e metadados globais

---

Estrutura do Repositório

undersoundpfc/
├── backend/
│   ├── app/
│   │   ├── routers/          # Rotas RESTful (auth.py, musicas.py)
│   │   ├── config.py         # Configurações e variáveis de ambiente
│   │   ├── database.py       # Conexão SQLAlchemy / MySQL
│   │   ├── external_services.py # Integração assíncrona com MusicBrainz + Fallback
│   │   ├── logger.py         # Sistema de auditoria operacional (auditoria.log)
│   │   ├── main.py           # Inicialização da API FastAPI e middlewares CORS
│   │   ├── models.py         # Entidades ORM (Usuario, Album, Musica)
│   │   ├── schemas.py        # Modelos de validação Pydantic
│   │   └── security.py       # Hash bcrypt e geração/validação de JWT
│   ├── uploads/              # Armazenamento local de áudios e capas
│   ├── .env.exemplo          # Modelo de variáveis de ambiente
│   └── requirements.txt      # Dependências Python
├── frontend/
│   ├── src/
│   │   ├── components/       # Player fixo, Modais, Navbar, etc.
│   │   ├── pages/            # Home (Catálogo), Dashboard, Login, Cadastro, etc.
│   │   └── services/         # Cliente HTTP Axios configurado
│   └── package.json          # Dependências Node/React
└── README.md                 # Documentação principal do projeto

Como executar o código localmente? 

1. Clone o repositório:(
git clone [https://github.com/gustavogdsilva/undersoundpfc.git](https://github.com/gustavogdsilva/undersoundpfc.git)
cd undersoundpfc
git checkout entregafinal)

2.Configuração e inicialização backend (na pasta /backend)
cd backend
python -m venv venv

3. Instale as dependências do Python
pip install -r requirements.txt

4. Crie um arquivo .env na pasta backend/ (.env.exemplo como base)
Exemplo de conteúdo: 
DATABASE_URL=mysql+pymysql://root:@localhost:3306/undersound_db
SECRET_KEY=sua_chave_secreta_jwt_aqui

5. Certifique-se de que o serviço MySQL esteja ativo e o banco undersound_db criado (as tabelas serão geradas automaticamente pelo SQLAlchemy na inicialização).

6. Inicie o server com o comando base: uvicorn app.main:app --reload --port 8000

Agora, vamos para o frontend, em outro terminal distinto.

1. Acesse a pasta frontend/ e insira o comando
cd frontend
npm install

2. Inicie o server dev do Vite:
npm run dev

3. Acesse a plataforma no navegador em: http://localhost:5173 (Ou o link de localhost que gerar)

Verá funcionando normalmente, cumprindo todas as funcionalidades necessárias!

Autoria e Orientação

Discente: Gustavo Gonçalves da Silva   

Orientador: Prof. Alessandro Horas   

Instituição: Universidade de Mogi das Cruzes (UMC) — Bacharelado em Engenharia de Software (2026)