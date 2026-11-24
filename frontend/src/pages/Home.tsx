import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Play, Disc, Trash2, PlusCircle, Upload, MoreVertical, Edit3, GripVertical, LogOut, LayoutDashboard, ShieldAlert, FileText, RefreshCw, X } from 'lucide-react';

const getApiBaseUrl = (): string => {
  const raw = (import.meta.env.VITE_API_URL || 'http://localhost:8000').trim();
  const withoutBrackets = raw.replace(/^\[+|\]+$/g, '');
  const withoutTrailingSlash = withoutBrackets.replace(/\/+$/, '');
  return withoutTrailingSlash.endsWith('/api')
    ? withoutTrailingSlash.slice(0, -4)
    : withoutTrailingSlash;
};

const API_BASE_URL = getApiBaseUrl();

const resolverUrlMidia = (path?: string): string | undefined => {
  if (!path) return undefined;
  if (path.startsWith('http://') || path.startsWith('https://')) {
    return path;
  }
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${API_BASE_URL}${normalizedPath}`;
};

const extrairDuracaoAudio = (file: File, fallbackSegundos = 0): Promise<number> => {
  return new Promise((resolve) => {
    const url = URL.createObjectURL(file);
    const audio = document.createElement('audio');
    audio.preload = 'metadata';

    const limparEResolver = (segundos: number) => {
      URL.revokeObjectURL(url);
      resolve(Number.isFinite(segundos) && segundos > 0 ? Math.round(segundos) : fallbackSegundos);
    };

    audio.onloadedmetadata = () => {
      limparEResolver(audio.duration);
    };

    audio.onerror = () => {
      limparEResolver(fallbackSegundos);
    };

    audio.src = url;
  });
};

interface Musica {
  id: number;
  titulo: string;
  duracao_segundos: number;
  arquivo_url: string;
  ordem?: number;
}

interface Album {
  id: number;
  titulo: string;
  ano: number;
  genero: string;
  capa_url: string;
  artista_id: number;
  artista_nome?: string;
  musicas: Musica[];
}

interface Track {
  id: number;
  titulo: string;
  artista: string;
  url: string;
  capa?: string;
}

interface HomeProps {
  onPlayTrack: (track: Track, albumTracks?: Track[]) => void;
}

const BotaoHover = ({ children, style, onClick, title, type = "button", variant = "primary", disabled = false }: any) => {
  const [hovered, setHovered] = useState(false);

  const getHoverStyle = () => {
    if (disabled) {
      return {
        backgroundColor: '#27272a',
        color: '#71717a',
        borderColor: '#3f3f46',
        cursor: 'not-allowed'
      };
    }
    if (variant === 'danger') {
      return {
        backgroundColor: hovered ? '#dc2626' : '#450a0a',
        color: hovered ? '#fff' : '#fca5a5',
        borderColor: '#7f1d1d'
      };
    }
    if (variant === 'secondary') {
      return {
        backgroundColor: hovered ? '#27272a' : '#18181b',
        color: '#fff',
        borderColor: hovered ? '#52525b' : '#3f3f46'
      };
    }
    if (variant === 'admin') {
      return {
        backgroundColor: hovered ? '#78350f' : '#451a03',
        color: '#fcd34d',
        borderColor: '#92400e'
      };
    }
    return {
      backgroundColor: hovered ? '#dc2626' : '#ef4444',
      color: '#fff'
    };
  };

  return (
    <button
      type={type}
      onClick={disabled ? undefined : onClick}
      disabled={disabled}
      title={title}
      onMouseEnter={() => !disabled && setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        ...style,
        ...getHoverStyle(),
        transform: hovered && !disabled ? 'translateY(-2px)' : 'translateY(0px)',
        boxShadow: hovered && !disabled ? '0 4px 12px rgba(239, 68, 68, 0.25)' : 'none',
        transition: 'all 0.2s ease',
        cursor: disabled ? 'not-allowed' : 'pointer'
      }}
    >
      {children}
    </button>
  );
};

export const Home: React.FC<HomeProps> = ({ onPlayTrack }) => {
  const [albuns, setAlbuns] = useState<Album[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [usuarioIdLogado, setUsuarioIdLogado] = useState<number | null>(null);
  const [tipoUsuario, setTipoUsuario] = useState<string>('');
  const [nomeUsuario, setNomeUsuario] = useState<string>('');
  
  // Modal Criar Álbum
  const [modalAlbumAberto, setModalAlbumAberto] = useState<boolean>(false);
  const [tituloAlbum, setTituloAlbum] = useState<string>('');
  const [anoAlbum, setAnoAlbum] = useState<number>(2026);
  const [generoAlbum, setGeneroAlbum] = useState<string>('');
  const [arquivoCapa, setArquivoCapa] = useState<File | null>(null);
  const [criandoAlbum, setCriandoAlbum] = useState<boolean>(false);
  const [erroCriacaoAlbum, setErroCriacaoAlbum] = useState<string>('');
  const [albumCriadoSucesso, setAlbumCriadoSucesso] = useState<boolean>(false);

  // Modal Editar Álbum
  const [modalEditarAlbumAberto, setModalEditarAlbumAberto] = useState<boolean>(false);
  const [albumEditandoId, setAlbumEditandoId] = useState<number | null>(null);
  const [tituloEditAlbum, setTituloEditAlbum] = useState<string>('');
  const [anoEditAlbum, setAnoEditAlbum] = useState<number>(2026);
  const [generoEditAlbum, setGeneroEditAlbum] = useState<string>('');
  const [arquivoEditCapa, setArquivoEditCapa] = useState<File | null>(null);
  const [musicasEditando, setMusicasEditando] = useState<Musica[]>([]);
  const [albumEditadoSucesso, setAlbumEditadoSucesso] = useState<boolean>(false);
  
  const [indiceArrastando, setIndiceArrastando] = useState<number | null>(null);
  const [menuAbertoId, setMenuAbertoId] = useState<number | null>(null);

  // Modal Upload de Música (Com Sucesso Visual)
  const [modalMusicaAberto, setModalMusicaAberto] = useState<boolean>(false);
  const [albumSelecionadoId, setAlbumSelecionadoId] = useState<number | null>(null);
  const [tituloMusica, setTituloMusica] = useState<string>('');
  const [duracaoMusica, setDuracaoMusica] = useState<number>(0);
  const [ordemMusica, setOrdemMusica] = useState<number>(1);
  const [arquivoAudio, setArquivoAudio] = useState<File | null>(null);
  const [enviandoMusica, setEnviandoMusica] = useState<boolean>(false);
  const [erroEnvioMusica, setErroEnvioMusica] = useState<string>('');
  const [musicaEnviadaSucesso, setMusicaEnviadaSucesso] = useState<boolean>(false);

  // Modal Consulta MusicBrainz
  const [modalGlobalAberto, setModalGlobalAberto] = useState<boolean>(false);
  const [termoBuscaGlobal, setTermoBuscaGlobal] = useState<string>('');
  const [resultadoGlobal, setResultadoGlobal] = useState<any>(null);

  // Modal Exclusão de Conta (LGPD - RF06)
  const [modalExcluirContaAberto, setModalExcluirContaAberto] = useState<boolean>(false);
  const [cienteExclusaoLgpd, setCienteExclusaoLgpd] = useState<boolean>(false);
  const [excluindoConta, setExcluindoConta] = useState<boolean>(false);
  const [erroExclusaoConta, setErroExclusaoConta] = useState<string>('');
  const [exclusaoConcluida, setExclusaoConcluida] = useState<boolean>(false);

  // Modal Unificado de Confirmação de Exclusão (Álbum / Música)
  const [modalConfirmacaoAberto, setModalConfirmacaoAberto] = useState<boolean>(false);
  const [tipoExclusao, setTipoExclusao] = useState<'album' | 'musica' | null>(null);
  const [idParaExcluir, setIdParaExcluir] = useState<number | null>(null);
  const [tituloItemExcluindo, setTituloItemExcluindo] = useState<string>('');
  const [itemExcluidoSucesso, setItemExcluidoSucesso] = useState<boolean>(false);
  const [mensagemSucessoExclusao, setMensagemSucessoExclusao] = useState<string>('');

  const [modalLogsAberto, setModalLogsAberto] = useState<boolean>(false);
  const [logsLinhas, setLogsLinhas] = useState<string[]>([]);
  const [carregandoLogs, setCarregandoLogs] = useState<boolean>(false);

  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('undersound_token');
    if (!token) {
      navigate('/login');
      return;
    }

    api.get('/auth/me')
      .then((res) => {
        setUsuarioIdLogado(res.data.id);
        setTipoUsuario(res.data.tipo_usuario);
        setNomeUsuario(res.data.nome || '');
      })
      .catch((err) => console.error("Erro ao carregar perfil:", err));

    carregarAlbuns();
  }, [navigate]);

  const carregarAlbuns = () => {
    api.get('/albuns')
      .then((res) => setAlbuns(res.data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  };

  const handleLogout = () => {
    localStorage.removeItem('undersound_token');
    navigate('/login');
  };

  const buscarLogsAdmin = async () => {
  setCarregandoLogs(true);
    try {
      const res = await api.get('/admin/logs?linhas=200');
      setLogsLinhas(res.data.linhas || []);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao buscar logs de auditoria.');
    } finally {
      setCarregandoLogs(false);
    }
  };

  const handleAbrirLogs = async () => {
    setModalLogsAberto(true);
    await buscarLogsAdmin();
  };

  const handleConsultarMusicBrainz = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!termoBuscaGlobal.trim()) return;

    try {
      const res = await api.get(`/albuns/consulta-externa/${encodeURIComponent(termoBuscaGlobal)}`);
      setResultadoGlobal(res.data);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao consultar o MusicBrainz.');
    }
  };

  const abrirModalCriarAlbum = () => {
    setTituloAlbum('');
    setGeneroAlbum('');
    setAnoAlbum(2026);
    setArquivoCapa(null);
    setErroCriacaoAlbum('');
    setAlbumCriadoSucesso(false);
    setModalAlbumAberto(true);
  };

  const handleCriarAlbum = async (e: React.FormEvent) => {
    e.preventDefault();
    setCriandoAlbum(true);
    setErroCriacaoAlbum('');

    try {
      const formData = new FormData();
      formData.append('titulo', tituloAlbum);
      formData.append('ano', String(anoAlbum));
      formData.append('genero', generoAlbum);
      if (arquivoCapa) formData.append('file', arquivoCapa);

      await api.post('/albuns/', formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setCriandoAlbum(false);
      setAlbumCriadoSucesso(true);
      carregarAlbuns();
    } catch (err: any) {
      setCriandoAlbum(false);
      setErroCriacaoAlbum(err.response?.data?.detail || 'Erro ao criar álbum.');
    }
  };

  const abrirModalEdicao = (album: Album) => {
    setAlbumEditandoId(album.id);
    setTituloEditAlbum(album.titulo);
    setAnoEditAlbum(album.ano);
    setGeneroEditAlbum(album.genero);
    const ordenadas = album.musicas ? [...album.musicas].sort((a, b) => (a.ordem || 1) - (b.ordem || 1)) : [];
    setMusicasEditando(ordenadas);
    setAlbumEditadoSucesso(false);
    setMenuAbertoId(null);
    setModalEditarAlbumAberto(true);
  };

  const handleDragStart = (e: React.DragEvent, index: number) => {
    setIndiceArrastando(index);
    e.dataTransfer.effectAllowed = 'move';
  };

  const handleDragOver = (e: React.DragEvent, index: number) => {
    e.preventDefault();
    if (indiceArrastando === null || indiceArrastando === index) return;

    const novasMusicas = [...musicasEditando];
    const itemMovido = novasMusicas.splice(indiceArrastando, 1)[0];
    novasMusicas.splice(index, 0, itemMovido);

    setIndiceArrastando(index);
    setMusicasEditando(novasMusicas);
  };

  const handleDragEnd = () => {
    setIndiceArrastando(null);
  };

  const handleEditarAlbumSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!albumEditandoId) return;

    try {
      const formData = new FormData();
      formData.append('titulo', tituloEditAlbum);
      formData.append('ano', String(anoEditAlbum));
      formData.append('genero', generoEditAlbum);
      if (arquivoEditCapa) formData.append('file', arquivoEditCapa);

      await api.put(`/albuns/${albumEditandoId}`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      for (let i = 0; i < musicasEditando.length; i++) {
        const musica = musicasEditando[i];
        const novaOrdem = i + 1;
        const formMusica = new FormData();
        formMusica.append('nova_ordem', String(novaOrdem));
        await api.patch(`/albuns/musicas/${musica.id}/ordem`, formMusica);
      }

      setAlbumEditadoSucesso(true);
      carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao editar álbum.');
    }
  };

  const abrirModalUploadMusica = (albumId: number) => {
    const albumAlvo = albuns.find((a) => a.id === albumId);
    const proximaOrdem = (albumAlvo?.musicas?.length || 0) + 1;

    setAlbumSelecionadoId(albumId);
    setTituloMusica('');
    setOrdemMusica(proximaOrdem);
    setDuracaoMusica(0);
    setArquivoAudio(null);
    setErroEnvioMusica('');
    setMusicaEnviadaSucesso(false);
    setModalMusicaAberto(true);
  };

  const handleSelecionarAudio = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0] || null;
    setArquivoAudio(file);

    if (file) {
      const duracaoDetectada = await extrairDuracaoAudio(file, 0);
      setDuracaoMusica(duracaoDetectada);
    } else {
      setDuracaoMusica(0);
    }
  };

  const handleUploadMusica = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!albumSelecionadoId || !arquivoAudio) {
      setErroEnvioMusica('Selecione um arquivo de áudio.');
      return;
    }

    setEnviandoMusica(true);
    setErroEnvioMusica('');

    const duracaoFinal =
      duracaoMusica > 0 ? duracaoMusica : await extrairDuracaoAudio(arquivoAudio, 0);

    const formData = new FormData();
    formData.append('titulo', tituloMusica);
    formData.append('duracao_segundos', String(duracaoFinal));
    formData.append('ordem', String(ordemMusica));
    formData.append('file', arquivoAudio);

    try {
      await api.post(`/albuns/${albumSelecionadoId}/upload-audio`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' }
      });

      setEnviandoMusica(false);
      setMusicaEnviadaSucesso(true);
      setDuracaoMusica(0);
      carregarAlbuns();
    } catch (err: any) {
      setEnviandoMusica(false);
      setErroEnvioMusica(err.response?.data?.detail || 'Erro ao enviar arquivo de áudio.');
    }
  };

  const solicitarExclusaoAlbum = (albumId: number, albumTitulo: string) => {
    setMenuAbertoId(null);
    setTipoExclusao('album');
    setIdParaExcluir(albumId);
    setTituloItemExcluindo(albumTitulo);
    setItemExcluidoSucesso(false);
    setModalConfirmacaoAberto(true);
  };

  const solicitarExclusaoMusica = (musicaId: number, musicaTitulo: string) => {
    setTipoExclusao('musica');
    setIdParaExcluir(musicaId);
    setTituloItemExcluindo(musicaTitulo);
    setItemExcluidoSucesso(false);
    setModalConfirmacaoAberto(true);
  };

  const confirmarExclusaoItem = async () => {
    if (!idParaExcluir || !tipoExclusao) return;

    try {
      if (tipoExclusao === 'album') {
        await api.delete(`/albuns/${idParaExcluir}`);
        setMensagemSucessoExclusao('O álbum e todas as suas faixas foram removidos permanentemente.');
      } else if (tipoExclusao === 'musica') {
        await api.delete(`/albuns/musicas/${idParaExcluir}`);
        setMensagemSucessoExclusao('A faixa foi removida com sucesso do álbum.');
      }
      setItemExcluidoSucesso(true);
      carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao realizar exclusão.');
    }
  };

  const abrirModalExcluirConta = () => {
    setCienteExclusaoLgpd(false);
    setErroExclusaoConta('');
    setExclusaoConcluida(false);
    setModalExcluirContaAberto(true);
  };

  const confirmarExclusaoConta = async () => {
    if (!cienteExclusaoLgpd) return;

    setExcluindoConta(true);
    setErroExclusaoConta('');

    try {
      await api.delete('/auth/conta/excluir');
      localStorage.removeItem('undersound_token');
      setExcluindoConta(false);
      setExclusaoConcluida(true);
    } catch (err: any) {
      setExcluindoConta(false);
      setErroExclusaoConta(err.response?.data?.detail || 'Erro ao tentar excluir a conta. Tente novamente.');
    }
  };
      
  return (
    <div style={{ padding: '32px', color: '#fff', backgroundColor: '#09090b', minHeight: 'calc(100vh - 60px)', paddingBottom: '90px' }}>
      
      {/* CABEÇALHO HORIZONTAL: LOGO À ESQUERDA | BOTÕES À DIREITA */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', borderBottom: '1px solid #27272a', paddingBottom: '20px' }}>
        
        {/* LADO ESQUERDO: LOGO COMPACTA + SAUDAÇÃO */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
            <div style={{ width: '3px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
            <div style={{ width: '3px', height: '18px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
            <div style={{ width: '3px', height: '26px', backgroundColor: '#fff', borderRadius: '2px' }}></div>
            <div style={{ width: '3px', height: '18px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
            <div style={{ width: '3px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          </div>

          <div>
            <h1 style={{ fontSize: '1.2rem', fontWeight: '900', letterSpacing: '1.5px', margin: 0, color: '#fff', lineHeight: '1.2' }}>
              UNDERSOUND
            </h1>
            <p style={{ color: '#a1a1aa', fontSize: '0.78rem', margin: '2px 0 0 0' }}>
              Bem-vindo(a), <strong style={{ color: '#fff' }}>{nomeUsuario || 'Usuário'}</strong> • Perfil: <strong style={{ color: tipoUsuario === 'admin' ? '#f59e0b' : '#ef4444' }}>{tipoUsuario.toUpperCase()}</strong>
            </p>
          </div>
        </div>

        {/* LADO DIREITO: BOTÕES DE AÇÃO */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
          <BotaoHover
              onClick={() => setModalGlobalAberto(true)}
              variant="secondary"
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46',
                padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
              }}
            >
              <Disc size={15} color="#ef4444" />
              Busca Global
            </BotaoHover>
          
          {tipoUsuario === 'admin' && (
            <BotaoHover
              onClick={handleAbrirLogs}
              variant="admin"
              style={{
                display: 'flex', alignItems: 'center', gap: '6px',
                backgroundColor: '#451a03', color: '#fcd34d', border: '1px solid #92400e',
                padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
              }}
            >
              <FileText size={15} />
              Ver Logs (Admin)
            </BotaoHover>
          )}

          {tipoUsuario === 'artista' && (
            <>
              <BotaoHover
                onClick={() => navigate('/dashboard')}
                variant="secondary"
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46',
                  padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
                }}
              >
                <LayoutDashboard size={15} color="#ef4444" />
                Meu Dashboard
              </BotaoHover>

              <BotaoHover
                onClick={abrirModalCriarAlbum}
                style={{
                  display: 'flex', alignItems: 'center', gap: '6px',
                  backgroundColor: '#ef4444', color: '#fff', border: 'none',
                  padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
                }}
              >
                <PlusCircle size={15} />
                Publicar Álbum
              </BotaoHover>
            </>
          )}

          <BotaoHover
            onClick={handleLogout}
            variant="secondary"
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46',
              padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
            }}
          >
            <LogOut size={15} />
            Sair
          </BotaoHover>

          <BotaoHover
            onClick={abrirModalExcluirConta}
            variant="danger"
            style={{
              display: 'flex', alignItems: 'center', gap: '6px',
              backgroundColor: '#450a0a', color: '#fca5a5', border: '1px solid #7f1d1d',
              padding: '8px 14px', borderRadius: '6px', fontSize: '0.82rem', fontWeight: 'bold'
            }}
          >
            <Trash2 size={15} />
            Excluir Conta
          </BotaoHover>
        </div>
      </div>

      {/* Modal de Logs de Auditoria (Admin) */}
      {modalLogsAberto && tipoUsuario === 'admin' && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1200, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '24px', borderRadius: '8px', border: '1px solid #3f3f46', width: '100%', maxWidth: '820px', maxHeight: '80vh', display: 'flex', flexDirection: 'column', gap: '12px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#fff', fontSize: '1.2rem' }}>Logs de Auditoria (Admin)</h3>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <BotaoHover
                  variant="secondary"
                  disabled={carregandoLogs}
                  onClick={buscarLogsAdmin}
                  style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 12px', backgroundColor: '#27272a', color: '#e4e4e7', border: '1px solid #3f3f46', borderRadius: '6px', fontSize: '0.8rem' }}
                >
                  <RefreshCw size={14} />
                  Atualizar
                </BotaoHover>
                <button
                  type="button"
                  onClick={() => setModalLogsAberto(false)}
                  style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', padding: '4px' }}
                  title="Fechar"
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            <div style={{ backgroundColor: '#09090b', border: '1px solid #27272a', borderRadius: '6px', padding: '12px', overflowY: 'auto', fontFamily: 'monospace', fontSize: '0.8rem', lineHeight: 1.5, whiteSpace: 'pre-wrap', flex: 1, color: '#e4e4e7' }}>
              {carregandoLogs
                ? 'Carregando logs...'
                : logsLinhas.length === 0
                ? 'Nenhum registro encontrado em auditoria.log.'
                : logsLinhas.join('\n')}
            </div>
          </div>
        </div>
      )}

      {/* Modal de Exclusão Consciente de Conta (LGPD - RF06) */}
      {modalExcluirContaAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1100, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: exclusaoConcluida ? '1px solid #15803d' : '1px solid #7f1d1d', width: '100%', maxWidth: '460px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            
            {exclusaoConcluida ? (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <div style={{
                  width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px auto', color: '#22c55e', fontSize: '1.6rem', fontWeight: 'bold'
                }}>
                  ✓
                </div>

                <h3 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '1.25rem' }}>
                  Conta Excluída com Sucesso
                </h3>

                <p style={{ fontSize: '0.88rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  Todos os seus dados pessoais, álbuns e faixas foram removidos permanentemente da plataforma em conformidade com a <strong style={{ color: '#e4e4e7' }}>LGPD (RF06)</strong>.
                </p>

                <BotaoHover
                  onClick={() => navigate('/login')}
                  style={{
                    width: '100%', padding: '10px 16px', backgroundColor: '#ef4444',
                    color: '#fff', border: 'none', borderRadius: '6px',
                    fontSize: '0.9rem', fontWeight: 'bold'
                  }}
                >
                  Voltar para a Tela de Login
                </BotaoHover>
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                  <ShieldAlert size={24} color="#ef4444" />
                  <h3 style={{ margin: 0, color: '#ef4444', fontSize: '1.2rem' }}>Exclusão Definitiva de Conta (LGPD)</h3>
                </div>
                
                <p style={{ fontSize: '0.88rem', color: '#d4d4d8', lineHeight: '1.5', marginBottom: '14px' }}>
                  Você está prestes a exercer o seu <strong>Direito ao Esquecimento</strong> previsto na Lei Geral de Proteção de Dados (Lei nº 13.709/2018).
                </p>
                
                <p style={{ fontSize: '0.82rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '16px' }}>
                  Esta operação é <strong>irreversível</strong>: seu perfil, credenciais de acesso e todos os álbuns ou faixas musicais vinculadas à sua conta serão apagados permanentemente da base de dados.
                </p>

                {erroExclusaoConta && (
                  <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px', borderRadius: '4px', marginBottom: '16px', fontSize: '0.8rem', border: '1px solid #7f1d1d' }}>
                    {erroExclusaoConta}
                  </div>
                )}

                <div style={{ backgroundColor: '#27272a', padding: '12px', borderRadius: '6px', border: '1px solid #3f3f46', marginBottom: '20px', display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                  <input
                    type="checkbox"
                    id="check-ciencia-lgpd"
                    checked={cienteExclusaoLgpd}
                    onChange={(e) => setCienteExclusaoLgpd(e.target.checked)}
                    style={{ marginTop: '3px', width: '16px', height: '16px', cursor: 'pointer', accentColor: '#ef4444' }}
                  />
                  <label htmlFor="check-ciencia-lgpd" style={{ fontSize: '0.82rem', color: '#e4e4e7', lineHeight: '1.4', cursor: 'pointer' }}>
                    Estou ciente de que todos os meus dados pessoais e conteúdos publicados serão excluídos permanentemente e não poderão ser recuperados.
                  </label>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                  <BotaoHover
                    variant="secondary"
                    disabled={excluindoConta}
                    onClick={() => setModalExcluirContaAberto(false)}
                    style={{ padding: '8px 16px', backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px', fontSize: '0.85rem' }}
                  >
                    Cancelar
                  </BotaoHover>

                  <BotaoHover
                    variant="danger"
                    disabled={!cienteExclusaoLgpd || excluindoConta}
                    onClick={confirmarExclusaoConta}
                    style={{
                      padding: '8px 16px',
                      border: '1px solid #7f1d1d',
                      borderRadius: '6px',
                      fontSize: '0.85rem',
                      fontWeight: 'bold'
                    }}
                  >
                    {excluindoConta ? 'Excluindo...' : 'Confirmar Exclusão Definitiva'}
                  </BotaoHover>
                </div>
              </>
            )}

          </div>
        </div>
      )}

      {/* Modal Criar Álbum */}
      {modalAlbumAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: albumCriadoSucesso ? '1px solid #15803d' : '1px solid #27272a', width: '100%', maxWidth: '420px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            
            {albumCriadoSucesso ? (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <div style={{
                  width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px auto', color: '#22c55e', fontSize: '1.6rem', fontWeight: 'bold'
                }}>
                  ✓
                </div>

                <h3 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '1.25rem' }}>
                  Álbum Publicado com Sucesso!
                </h3>

                <p style={{ fontSize: '0.88rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  O seu novo álbum já está cadastrado na plataforma e pronto para receber faixas e reproduções.
                </p>

                <BotaoHover
                  onClick={() => setModalAlbumAberto(false)}
                  style={{
                    width: '100%', padding: '10px 16px', backgroundColor: '#ef4444',
                    color: '#fff', border: 'none', borderRadius: '6px',
                    fontSize: '0.9rem', fontWeight: 'bold'
                  }}
                >
                  Concluir e Ver Catálogo
                </BotaoHover>
              </div>
            ) : (
              <form onSubmit={handleCriarAlbum}>
                <h3 style={{ marginTop: 0, marginBottom: '16px', fontSize: '1.2rem', color: '#fff' }}>Cadastrar Novo Álbum</h3>
                
                {erroCriacaoAlbum && (
                  <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.8rem', border: '1px solid #7f1d1d' }}>
                    {erroCriacaoAlbum}
                  </div>
                )}

                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título do Álbum</label>
                  <input type="text" value={tituloAlbum} onChange={(e) => setTituloAlbum(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Gênero Musical</label>
                  <input type="text" value={generoAlbum} onChange={(e) => setGeneroAlbum(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Ano</label>
                  <input type="number" value={anoAlbum} onChange={(e) => setAnoAlbum(Number(e.target.value))} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Foto de Capa do Álbum (Imagem)</label>
                  <input type="file" accept="image/*" onChange={(e) => setArquivoCapa(e.target.files ? e.target.files[0] : null)} style={{ width: '100%', marginTop: '4px', color: '#fff' }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <BotaoHover variant="secondary" disabled={criandoAlbum} onClick={() => setModalAlbumAberto(false)} style={{ padding: '8px 16px', backgroundColor: '#27272a', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px' }}>Cancelar</BotaoHover>
                  <BotaoHover type="submit" disabled={criandoAlbum} style={{ padding: '8px 16px', backgroundColor: '#ef4444', color: '#fff', fontWeight: 'bold', border: 'none', borderRadius: '6px' }}>
                    {criandoAlbum ? 'Salvando...' : 'Salvar Álbum'}
                  </BotaoHover>
                </div>
              </form>
            )}

          </div>
        </div>
      )}

      {/* Modal Upload de Música (Com Feedback Visual de Sucesso) */}
      {modalMusicaAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: musicaEnviadaSucesso ? '1px solid #15803d' : '1px solid #27272a', width: '100%', maxWidth: '420px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            
            {musicaEnviadaSucesso ? (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <div style={{
                  width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px auto', color: '#22c55e', fontSize: '1.6rem', fontWeight: 'bold'
                }}>
                  ✓
                </div>

                <h3 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '1.25rem' }}>
                  Música Enviada com Sucesso!
                </h3>

                <p style={{ fontSize: '0.88rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  O arquivo de áudio foi associado ao álbum e já está disponível para reprodução na plataforma.
                </p>

                <BotaoHover
                  onClick={() => setModalMusicaAberto(false)}
                  style={{
                    width: '100%', padding: '10px 16px', backgroundColor: '#ef4444',
                    color: '#fff', border: 'none', borderRadius: '6px',
                    fontSize: '0.9rem', fontWeight: 'bold'
                  }}
                >
                  Concluir
                </BotaoHover>
              </div>
            ) : (
              <form onSubmit={handleUploadMusica}>
                <h3 style={{ marginTop: 0, marginBottom: '16px', fontSize: '1.2rem', color: '#fff' }}>Adicionar Música Local</h3>
                
                {erroEnvioMusica && (
                  <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.8rem', border: '1px solid #7f1d1d' }}>
                    {erroEnvioMusica}
                  </div>
                )}

                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título da Música</label>
                  <input type="text" value={tituloMusica} onChange={(e) => setTituloMusica(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                <div style={{ marginBottom: '20px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Arquivo de Áudio (.mp3, .wav, .mpeg)</label>
                  <input type="file" accept="audio/*,video/mpeg,.mpeg,.mpg" onChange={handleSelecionarAudio} required style={{ width: '100%', marginTop: '4px', color: '#fff' }} />
                  {arquivoAudio && duracaoMusica > 0 && (
                    <small style={{ display: 'block', marginTop: '6px', color: '#a1a1aa', fontSize: '0.75rem' }}>
                      Duração detectada: {duracaoMusica}s (faixa #{ordemMusica})
                    </small>
                  )}
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <BotaoHover variant="secondary" disabled={enviandoMusica} onClick={() => setModalMusicaAberto(false)} style={{ padding: '8px 16px', backgroundColor: '#27272a', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px' }}>Cancelar</BotaoHover>
                  <BotaoHover type="submit" disabled={enviandoMusica} style={{ padding: '8px 16px', backgroundColor: '#ef4444', color: '#fff', fontWeight: 'bold', border: 'none', borderRadius: '6px' }}>
                    {enviandoMusica ? 'Enviando...' : 'Enviar Áudio'}
                  </BotaoHover>
                </div>
              </form>
            )}

          </div>
        </div>
      )}

      {/* Modal Unificado de Confirmação de Exclusão (Álbum / Música) */}
      {modalConfirmacaoAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1100, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: itemExcluidoSucesso ? '1px solid #15803d' : '1px solid #7f1d1d', width: '100%', maxWidth: '420px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            
            {itemExcluidoSucesso ? (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <div style={{
                  width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px auto', color: '#22c55e', fontSize: '1.6rem', fontWeight: 'bold'
                }}>
                  ✓
                </div>

                <h3 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '1.25rem' }}>
                  {tipoExclusao === 'album' ? 'Álbum Excluído!' : 'Música Excluída!'}
                </h3>

                <p style={{ fontSize: '0.88rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  {mensagemSucessoExclusao}
                </p>

                <BotaoHover
                  onClick={() => {
                    setModalConfirmacaoAberto(false);
                    setItemExcluidoSucesso(false);
                  }}
                  style={{
                    width: '100%', padding: '10px 16px', backgroundColor: '#ef4444',
                    color: '#fff', border: 'none', borderRadius: '6px',
                    fontSize: '0.9rem', fontWeight: 'bold'
                  }}
                >
                  Continuar
                </BotaoHover>
              </div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px' }}>
                  <ShieldAlert size={24} color="#ef4444" />
                  <h3 style={{ margin: 0, color: '#ef4444', fontSize: '1.2rem' }}>
                    {tipoExclusao === 'album' ? 'Excluir Álbum Definitivamente' : 'Excluir Música'}
                  </h3>
                </div>
                
                <p style={{ fontSize: '0.88rem', color: '#d4d4d8', lineHeight: '1.5', marginBottom: '14px' }}>
                  Tem certeza que deseja excluir {tipoExclusao === 'album' ? 'o álbum' : 'a faixa'} <strong style={{ color: '#fff' }}>"{tituloItemExcluindo}"</strong>?
                </p>
                
                <p style={{ fontSize: '0.82rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  {tipoExclusao === 'album' 
                    ? 'Esta ação removerá o álbum e todas as faixas associadas permanentemente da base de dados.' 
                    : 'Esta música será removida permanentemente da lista do álbum.'}
                </p>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                  <BotaoHover
                    variant="secondary"
                    onClick={() => setModalConfirmacaoAberto(false)}
                    style={{ padding: '8px 16px', backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px', fontSize: '0.85rem' }}
                  >
                    Cancelar
                  </BotaoHover>

                  <BotaoHover
                    variant="danger"
                    onClick={confirmarExclusaoItem}
                    style={{ padding: '8px 16px', border: '1px solid #7f1d1d', borderRadius: '6px', fontSize: '0.85rem', fontWeight: 'bold' }}
                  >
                    Sim, Excluir
                  </BotaoHover>
                </div>
              </>
            )}

          </div>
        </div>
      )}

      {/* Modal Consulta Global (MusicBrainz) */}
      {modalGlobalAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1200, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: '1px solid #27272a', width: '100%', maxWidth: '450px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            <h3 style={{ marginTop: 0, marginBottom: '8px', color: '#fff', fontSize: '1.2rem' }}>Consulta Global (MusicBrainz)</h3>
            <p style={{ fontSize: '0.82rem', color: '#a1a1aa', marginBottom: '16px', lineHeight: '1.4' }}>
              Consulte metadados oficiais de artistas na base de dados internacional.
            </p>

            <form onSubmit={handleConsultarMusicBrainz} style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
              <input 
                type="text" 
                placeholder="Ex: Sepultura, Nirvana..." 
                value={termoBuscaGlobal}
                onChange={(e) => setTermoBuscaGlobal(e.target.value)}
                style={{ flex: 1, padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', outline: 'none' }}
                required 
              />
              <BotaoHover type="submit" style={{ padding: '10px 16px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '6px', fontWeight: 'bold' }}>
                Buscar
              </BotaoHover>
            </form>

            {resultadoGlobal && (
              <div style={{ backgroundColor: '#27272a', padding: '14px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.85rem', border: '1px solid #3f3f46' }}>
                {resultadoGlobal.nome ? (
                  <>
                    <p style={{ margin: '0 0 6px 0' }}><strong>Nome:</strong> {resultadoGlobal.nome}</p>
                    <p style={{ margin: '0 0 6px 0' }}><strong>País:</strong> {resultadoGlobal.pais}</p>
                    <p style={{ margin: '0 0 6px 0' }}><strong>Tipo:</strong> {resultadoGlobal.tipo}</p>
                    {resultadoGlobal.disambiguation && (
                      <p style={{ margin: 0, color: '#a1a1aa' }}><em>{resultadoGlobal.disambiguation}</em></p>
                    )}
                  </>
                ) : (
                  <p style={{ margin: 0, color: '#a1a1aa' }}>{resultadoGlobal.mensagem || 'Nenhum resultado encontrado.'}</p>
                )}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <BotaoHover variant="secondary" onClick={() => { setModalGlobalAberto(false); setResultadoGlobal(null); setTermoBuscaGlobal(''); }} style={{ padding: '8px 16px', backgroundColor: '#18181b', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px' }}>
                Fechar
              </BotaoHover>
            </div>
          </div>
        </div>
      )}

      {/* Modal Editar Álbum com Feedback Visual de Sucesso */}
      {modalEditarAlbumAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1000, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: albumEditadoSucesso ? '1px solid #15803d' : '1px solid #27272a', width: '100%', maxWidth: '450px', maxHeight: '90vh', overflowY: 'auto', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.7)' }}>
            
            {albumEditadoSucesso ? (
              <div style={{ textAlign: 'center', padding: '12px 0' }}>
                <div style={{
                  width: '56px', height: '56px', borderRadius: '50%', backgroundColor: 'rgba(34, 197, 94, 0.15)',
                  border: '1px solid #22c55e', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  margin: '0 auto 16px auto', color: '#22c55e', fontSize: '1.6rem', fontWeight: 'bold'
                }}>
                  ✓
                </div>

                <h3 style={{ margin: '0 0 10px 0', color: '#fff', fontSize: '1.25rem' }}>
                  Álbum Atualizado com Sucesso!
                </h3>

                <p style={{ fontSize: '0.88rem', color: '#a1a1aa', lineHeight: '1.5', marginBottom: '24px' }}>
                  As alterações de metadados e a nova ordenação das faixas foram salvas na base de dados.
                </p>

                <BotaoHover
                  onClick={() => {
                    setModalEditarAlbumAberto(false);
                    setAlbumEditandoId(null);
                    setArquivoEditCapa(null);
                  }}
                  style={{
                    width: '100%', padding: '10px 16px', backgroundColor: '#ef4444',
                    color: '#fff', border: 'none', borderRadius: '6px',
                    fontSize: '0.9rem', fontWeight: 'bold'
                  }}
                >
                  Concluir
                </BotaoHover>
              </div>
            ) : (
              <form onSubmit={handleEditarAlbumSubmit}>
                <h3 style={{ marginTop: 0, marginBottom: '16px', color: '#fff', fontSize: '1.2rem' }}>Editar Álbum & Organizar Faixas</h3>
                
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título do Álbum</label>
                  <input type="text" value={tituloEditAlbum} onChange={(e) => setTituloEditAlbum(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Gênero Musical</label>
                  <input type="text" value={generoEditAlbum} onChange={(e) => setGeneroEditAlbum(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>
                
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Ano</label>
                  <input type="number" value={anoEditAlbum} onChange={(e) => setAnoEditAlbum(Number(e.target.value))} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
                </div>

                <div style={{ marginBottom: '16px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Nova Capa (Opcional)</label>
                  <input type="file" accept="image/*" onChange={(e) => setArquivoEditCapa(e.target.files ? e.target.files[0] : null)} style={{ width: '100%', marginTop: '4px', color: '#fff' }} />
                </div>

                <div style={{ marginBottom: '20px' }}>
                  <label style={{ fontSize: '0.85rem', color: '#a1a1aa', display: 'block', marginBottom: '4px' }}>
                    Arraste as faixas para reordenar:
                  </label>
                  {musicasEditando.length === 0 ? (
                    <p style={{ fontSize: '0.8rem', color: '#71717a' }}>Nenhuma música neste álbum.</p>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '200px', overflowY: 'auto', paddingRight: '4px' }}>
                      {musicasEditando.map((musica, index) => (
                        <div 
                          key={musica.id} 
                          draggable
                          onDragStart={(e) => handleDragStart(e, index)}
                          onDragOver={(e) => handleDragOver(e, index)}
                          onDragEnd={handleDragEnd}
                          style={{ 
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between', 
                            backgroundColor: '#27272a', padding: '8px 10px', borderRadius: '6px', 
                            cursor: 'grab', border: '1px solid #3f3f46' 
                          }}
                        >
                          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
                            <GripVertical size={16} color="#71717a" />
                            <span style={{ fontSize: '0.8rem', color: '#ef4444', fontWeight: 'bold', minWidth: '20px' }}>
                              {index + 1}.
                            </span>
                            <span style={{ fontSize: '0.85rem', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '300px' }}>
                              {musica.titulo}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <BotaoHover variant="secondary" onClick={() => setModalEditarAlbumAberto(false)} style={{ padding: '8px 16px', backgroundColor: '#27272a', color: '#fff', border: '1px solid #3f3f46', borderRadius: '6px' }}>Cancelar</BotaoHover>
                  <BotaoHover type="submit" style={{ padding: '8px 16px', backgroundColor: '#ef4444', color: '#fff', fontWeight: 'bold', border: 'none', borderRadius: '6px' }}>Salvar Alterações</BotaoHover>
                </div>
              </form>
            )}

          </div>
        </div>
      )}
      
      {loading ? (
        <p style={{ color: '#a1a1aa' }}>Carregando catálogo...</p>
      ) : albuns.length === 0 ? (
        <p style={{ color: '#a1a1aa' }}>Nenhum álbum cadastrado no momento.</p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '24px' }}>
          {albuns.map((album) => {
            const eAdmin = tipoUsuario === 'admin';
            const eDonoDoAlbum = tipoUsuario === 'artista' && usuarioIdLogado === album.artista_id;
            const podeGerenciar = eAdmin || eDonoDoAlbum;
            const capaResolvida = resolverUrlMidia(album.capa_url);

            return (
              <div key={album.id} style={{ backgroundColor: '#18181b', borderRadius: '8px', border: '1px solid #27272a', padding: '16px', position: 'relative' }}>
                
                {/* Cabeçalho do Card */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '0.75rem', color: '#71717a' }}>ID: #{album.id}</span>
                  {podeGerenciar && (
                    <div style={{ position: 'relative' }}>
                      <button 
                        onClick={() => setMenuAbertoId(menuAbertoId === album.id ? null : album.id)}
                        style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', padding: '4px', display: 'flex', alignItems: 'center' }}
                        title="Opções do Álbum"
                      >
                        <MoreVertical size={18} />
                      </button>

                      {menuAbertoId === album.id && (
                        <div style={{ 
                          position: 'absolute', right: 0, top: '24px', 
                          backgroundColor: '#27272a', border: '1px solid #3f3f46', 
                          borderRadius: '6px', boxShadow: '0 4px 12px rgba(0,0,0,0.5)', 
                          zIndex: 50, width: '130px', overflow: 'hidden' 
                        }}>
                          <button 
                            onClick={() => abrirModalEdicao(album)}
                            style={{ 
                              width: '100%', padding: '8px 12px', background: 'none', border: 'none', 
                              color: '#fff', textAlign: 'left', cursor: 'pointer', fontSize: '0.8rem', 
                              display: 'flex', alignItems: 'center', gap: '6px' 
                            }}
                          >
                            <Edit3 size={14} /> Editar
                          </button>
                          <button 
                            onClick={() => solicitarExclusaoAlbum(album.id, album.titulo)}
                            style={{ 
                              width: '100%', padding: '8px 12px', background: 'none', border: 'none', 
                              color: '#ef4444', textAlign: 'left', cursor: 'pointer', fontSize: '0.8rem', 
                              display: 'flex', alignItems: 'center', gap: '6px' 
                            }}
                          >
                            <Trash2 size={14} /> Excluir
                          </button>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                <div style={{ width: '100%', height: '180px', backgroundColor: '#27272a', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px', overflow: 'hidden' }}>
                  {capaResolvida ? (
                    <img src={capaResolvida} alt={album.titulo} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  ) : (
                    <Disc size={48} color="#71717a" />
                  )}
                </div>
                
                <h3 style={{ margin: '0 0 4px 0' }}>{album.titulo}</h3>
                <p style={{ margin: '0 0 4px 0', fontSize: '0.85rem', color: '#a1a1aa' }}>
                  {album.genero} • {album.ano}
                </p>
                <p style={{ margin: '0 0 12px 0', fontSize: '0.8rem', color: '#ef4444', fontWeight: 'bold' }}>
                  Por: {album.artista_nome || 'Artista Underground'}
                </p>

                {/* Listagem de músicas */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
                  {album.musicas && album.musicas.map((musica) => (
                    <div key={musica.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', backgroundColor: '#27272a', borderRadius: '4px' }}>
                      <span style={{ fontSize: '0.9rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '170px' }}>
                        {musica.ordem ? `${musica.ordem}. ` : ''}{musica.titulo}
                      </span>
                      
                      <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                        <button 
                          onClick={() => {
                            const playlistAlbum = album.musicas.map(m => ({
                              id: m.id,
                              titulo: m.titulo,
                              artista: album.titulo,
                              url: m.arquivo_url,
                              capa: capaResolvida
                            }));

                            onPlayTrack({
                              id: musica.id,
                              titulo: musica.titulo,
                              artista: album.titulo,
                              url: musica.arquivo_url,
                              capa: capaResolvida
                            }, playlistAlbum);
                          }} 
                          style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer' }}
                          title="Reproduzir faixa"
                        >
                          <Play size={16} />
                        </button>

                        {podeGerenciar && (
                          <button 
                            onClick={() => solicitarExclusaoMusica(musica.id, musica.titulo)} 
                            style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer' }}
                            title="Excluir música"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {eDonoDoAlbum && (
                  <div style={{ display: 'flex', gap: '8px', marginTop: '8px' }}>
                    <BotaoHover
                      variant="secondary"
                      onClick={() => abrirModalUploadMusica(album.id)}
                      style={{
                        flex: 1, padding: '8px', backgroundColor: '#27272a', color: '#ef4444',
                        border: '1px dashed #ef4444', borderRadius: '4px',
                        fontSize: '0.8rem', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px'
                      }}
                    >
                      <Upload size={14} /> Adicionar Música
                    </BotaoHover>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};