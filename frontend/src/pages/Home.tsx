import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import {
  Play,
  Disc,
  Trash2,
  PlusCircle,
  Upload,
  LogOut,
  LayoutDashboard,
  Search,
  FileText,
  X,
  RefreshCw,
} from 'lucide-react';

interface Musica {
  id: number;
  titulo: string;
  duracao_segundos: number;
  arquivo_url: string;
}

interface Album {
  id: number;
  titulo: string;
  ano: number;
  genero: string;
  capa_url: string;
  artista_id?: number | null;
  artista_nome?: string | null;
  musicas: Musica[];
}

interface TrackPayload {
  id: number;
  titulo: string;
  artista: string;
  url: string;
  capa?: string;
}

interface HomeProps {
  onPlayTrack: (track: TrackPayload, albumTracks?: TrackPayload[]) => void;
  onResetPlayer?: () => void;
}

interface BotaoHoverProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'admin';
  children: React.ReactNode;
}

const BotaoHover: React.FC<BotaoHoverProps> = ({
  variant = 'primary',
  style,
  children,
  onMouseEnter,
  onMouseLeave,
  ...rest
}) => {
  const [hovered, setHovered] = useState(false);

  const hoverStyles: Record<string, React.CSSProperties> = {
    primary: {
      backgroundColor: hovered ? '#dc2626' : '#ef4444',
      transform: hovered ? 'translateY(-1px)' : 'none',
    },
    secondary: {
      backgroundColor: hovered ? '#27272a' : '#18181b',
      borderColor: hovered ? '#52525b' : '#3f3f46',
    },
    danger: {
      backgroundColor: hovered ? '#7f1d1d' : '#450a0a',
    },
    admin: {
      backgroundColor: hovered ? '#78350f' : '#451a03',
    },
  };

  return (
    <button
      {...rest}
      style={{
        transition: 'all 0.15s ease',
        ...style,
        ...hoverStyles[variant],
      }}
      onMouseEnter={(e) => {
        setHovered(true);
        onMouseEnter?.(e);
      }}
      onMouseLeave={(e) => {
        setHovered(false);
        onMouseLeave?.(e);
      }}
    >
      {children}
    </button>
  );
};

export const Home: React.FC<HomeProps> = ({ onPlayTrack, onResetPlayer }) => {
  const [albuns, setAlbuns] = useState<Album[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [estaLogado, setEstaLogado] = useState<boolean>(false);
  const [nomeUsuario, setNomeUsuario] = useState<string>('');
  const [tipoUsuario, setTipoUsuario] = useState<string>('');
  const [usuarioIdLogado, setUsuarioIdLogado] = useState<number | null>(null);

  // Modal Criar Álbum
  const [modalAlbumAberto, setModalAlbumAberto] = useState<boolean>(false);
  const [tituloAlbum, setTituloAlbum] = useState<string>('');
  const [anoAlbum, setAnoAlbum] = useState<number>(2026);
  const [generoAlbum, setGeneroAlbum] = useState<string>('');
  const [capaUrl, setCapaUrl] = useState<string>('');

  // Modal Upload de Música
  const [modalMusicaAberto, setModalMusicaAberto] = useState<boolean>(false);
  const [albumSelecionadoId, setAlbumSelecionadoId] = useState<number | null>(null);
  const [tituloMusica, setTituloMusica] = useState<string>('');
  const [duracaoMusica, setDuracaoMusica] = useState<number>(180);
  const [arquivoAudio, setArquivoAudio] = useState<File | null>(null);

  // Modal Busca Global
  const [modalGlobalAberto, setModalGlobalAberto] = useState<boolean>(false);
  const [termoBusca, setTermoBusca] = useState<string>('');
  const [resultadosBusca, setResultadosBusca] = useState<any[]>([]);
  const [buscandoGlobal, setBuscandoGlobal] = useState<boolean>(false);

  // Modal de Logs para Admin
  const [modalLogsAberto, setModalLogsAberto] = useState<boolean>(false);
  const [logsLinhas, setLogsLinhas] = useState<string[]>([]);
  const [carregandoLogs, setCarregandoLogs] = useState<boolean>(false);

  const navigate = useNavigate();

  const carregarAlbuns = async () => {
    setLoading(true);
    try {
      const res = await api.get('/albuns/');
      setAlbuns(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const carregarPerfilAtual = async () => {
    const token = localStorage.getItem('undersound_token');
    if (!token) {
      setEstaLogado(false);
      setNomeUsuario('');
      setTipoUsuario('');
      setUsuarioIdLogado(null);
      return;
    }

    setEstaLogado(true);
    try {
      const res = await api.get('/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      });
      setNomeUsuario(res.data.nome || '');
      setTipoUsuario(res.data.tipo_usuario || '');
      setUsuarioIdLogado(res.data.id ?? null);
    } catch (err) {
      console.error('Erro ao carregar perfil:', err);
    }
  };

  useEffect(() => {
    carregarPerfilAtual();
    carregarAlbuns();
  }, []);

  const handleLogout = () => {
    onResetPlayer?.();
    localStorage.removeItem('undersound_token');
    navigate('/login');
  };

  const handleCriarAlbum = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem('undersound_token');
      await api.post(
        '/albuns/',
        {
          titulo: tituloAlbum,
          ano: Number(anoAlbum),
          genero: generoAlbum,
          capa_url: capaUrl,
        },
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      alert('Álbum criado com sucesso!');
      setModalAlbumAberto(false);
      setTituloAlbum('');
      setGeneroAlbum('');
      setCapaUrl('');
      await carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao criar álbum.');
    }
  };

  const handleUploadMusica = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!albumSelecionadoId || !arquivoAudio) {
      alert('Selecione um arquivo de áudio.');
      return;
    }

    const formData = new FormData();
    formData.append('titulo', tituloMusica);
    formData.append('duracao_segundos', String(duracaoMusica));
    formData.append('file', arquivoAudio);

    try {
      const token = localStorage.getItem('undersound_token');
      await api.post(`/albuns/${albumSelecionadoId}/upload-audio`, formData, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data',
        },
      });

      alert('Música enviada com sucesso!');
      setModalMusicaAberto(false);
      setTituloMusica('');
      setArquivoAudio(null);
      await carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao enviar arquivo de áudio.');
    }
  };

  const handleBuscaGlobal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!termoBusca.trim()) return;
    setBuscandoGlobal(true);
    try {
      const res = await api.get(`/albuns/buscar-global?q=${encodeURIComponent(termoBusca.trim())}`);
      setResultadosBusca(Array.isArray(res.data) ? res.data : res.data.resultados || []);
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro na busca global.');
    } finally {
      setBuscandoGlobal(false);
    }
  };

  const buscarLogsAdmin = async () => {
    setCarregandoLogs(true);
    try {
      const token = localStorage.getItem('undersound_token');
      const res = await api.get('/api/admin/logs?linhas=200', {
        headers: { Authorization: `Bearer ${token}` },
      });
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

  const podeGerenciarAlbum = (album: Album) => {
    if (!estaLogado) return false;
    if (tipoUsuario === 'admin') return true;
    return (
      tipoUsuario === 'artista' &&
      album.artista_id != null &&
      album.artista_id === usuarioIdLogado
    );
  };

  const handleExcluirMusica = async (musicaId: number) => {
    if (!window.confirm('Deseja realmente excluir esta música?')) return;

    try {
      const token = localStorage.getItem('undersound_token');
      await api.delete(`/albuns/musicas/${musicaId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert('Música excluída com sucesso!');
      await carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao excluir música.');
    }
  };

  const handleExcluirAlbum = async (albumId: number) => {
    if (
      !window.confirm(
        'Atenção: Excluir o álbum removerá todas as músicas associadas permanentemente.'
      )
    ) {
      return;
    }

    try {
      const token = localStorage.getItem('undersound_token');
      await api.delete(`/albuns/${albumId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert('Álbum excluído com sucesso!');
      await carregarAlbuns();
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao excluir álbum.');
    }
  };

  const handleExcluirConta = async () => {
    const confirmacao = window.confirm(
      'Atenção (LGPD - RF06): Deseja realmente excluir sua conta e todos os seus dados pessoais permanentemente? Esta ação não pode ser desfeita.'
    );

    if (!confirmacao) return;

    try {
      const token = localStorage.getItem('undersound_token');
      await api.delete('/auth/conta/excluir', {
        headers: { Authorization: `Bearer ${token}` },
      });

      onResetPlayer?.();
      localStorage.removeItem('undersound_token');
      alert('Sua conta e dados foram excluídos com sucesso em conformidade com a LGPD.');
      navigate('/login');
    } catch (err: any) {
      alert(err.response?.data?.detail || 'Erro ao tentar excluir a conta.');
    }
  };

  return (
    <div
      style={{
        padding: '32px',
        color: '#fff',
        backgroundColor: '#09090b',
        minHeight: 'calc(100vh - 60px)',
        paddingBottom: '90px',
      }}
    >
      {/* CABEÇALHO UNIFICADO */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '32px',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid #27272a',
          paddingBottom: '20px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '3px' }}>
            <div style={{ width: '3px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            <div style={{ width: '3px', height: '18px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            <div style={{ width: '3px', height: '26px', backgroundColor: '#fff', borderRadius: '2px' }} />
            <div style={{ width: '3px', height: '18px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
            <div style={{ width: '3px', height: '12px', backgroundColor: '#ef4444', borderRadius: '2px' }} />
          </div>
          <div>
            <h1 style={{ fontSize: '1.25rem', fontWeight: '900', letterSpacing: '1.5px', margin: 0, color: '#fff' }}>
              UNDERSOUND
            </h1>
            <p style={{ color: '#a1a1aa', fontSize: '0.78rem', margin: '2px 0 0 0' }}>
              Bem-vindo(a), <strong style={{ color: '#fff' }}>{nomeUsuario || 'Usuário'}</strong> • Perfil:{' '}
              <strong style={{ color: tipoUsuario === 'admin' ? '#f59e0b' : '#ef4444' }}>
                {(tipoUsuario || 'VISITANTE').toUpperCase()}
              </strong>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', alignItems: 'center' }}>
          <BotaoHover
            type="button"
            onClick={() => setModalGlobalAberto(true)}
            variant="secondary"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              backgroundColor: '#18181b',
              color: '#fff',
              border: '1px solid #3f3f46',
              padding: '8px 14px',
              borderRadius: '6px',
              fontSize: '0.85rem',
              fontWeight: 'bold',
              cursor: 'pointer',
            }}
          >
            <Search size={15} color="#ef4444" />
            Busca Global
          </BotaoHover>

          {tipoUsuario === 'artista' && (
            <>
              <BotaoHover
                type="button"
                onClick={() => navigate('/dashboard')}
                variant="secondary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#18181b',
                  color: '#fff',
                  border: '1px solid #3f3f46',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  cursor: 'pointer',
                }}
              >
                <LayoutDashboard size={15} color="#ef4444" />
                Meu Dashboard
              </BotaoHover>

              <BotaoHover
                type="button"
                onClick={() => setModalAlbumAberto(true)}
                variant="primary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#ef4444',
                  color: '#fff',
                  border: 'none',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  cursor: 'pointer',
                }}
              >
                <PlusCircle size={15} />
                Publicar Álbum
              </BotaoHover>
            </>
          )}

          {tipoUsuario === 'admin' && (
            <BotaoHover
              type="button"
              onClick={handleAbrirLogs}
              variant="admin"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: '#451a03',
                color: '#fcd34d',
                border: '1px solid #92400e',
                padding: '8px 14px',
                borderRadius: '6px',
                fontSize: '0.85rem',
                fontWeight: 'bold',
                cursor: 'pointer',
              }}
            >
              <FileText size={15} />
              Ver Logs (Admin)
            </BotaoHover>
          )}

          {estaLogado && (
            <>
              <BotaoHover
                type="button"
                onClick={handleLogout}
                variant="secondary"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#18181b',
                  color: '#fff',
                  border: '1px solid #3f3f46',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  cursor: 'pointer',
                }}
              >
                <LogOut size={15} />
                Sair
              </BotaoHover>

              <BotaoHover
                type="button"
                onClick={handleExcluirConta}
                variant="danger"
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  backgroundColor: '#450a0a',
                  color: '#fca5a5',
                  border: '1px solid #7f1d1d',
                  padding: '8px 14px',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  fontWeight: 'bold',
                  cursor: 'pointer',
                }}
              >
                <Trash2 size={15} />
                Excluir Conta
              </BotaoHover>
            </>
          )}
        </div>
      </div>

      {/* CATÁLOGO */}
      {loading ? (
        <p style={{ color: '#a1a1aa' }}>Carregando catálogo...</p>
      ) : albuns.length === 0 ? (
        <p style={{ color: '#a1a1aa' }}>Nenhum álbum cadastrado no momento.</p>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
            gap: '24px',
          }}
        >
          {albuns.map((album) => {
            const permiteGerenciar = podeGerenciarAlbum(album);
            const albumTracks: TrackPayload[] = (album.musicas || []).map((m) => ({
              id: m.id,
              titulo: m.titulo,
              artista: album.artista_nome || album.titulo,
              url: m.arquivo_url,
              capa: album.capa_url,
            }));

            return (
              <div
                key={album.id}
                style={{
                  backgroundColor: '#18181b',
                  borderRadius: '8px',
                  border: '1px solid #27272a',
                  padding: '16px',
                }}
              >
                <div
                  style={{
                    width: '100%',
                    height: '180px',
                    backgroundColor: '#27272a',
                    borderRadius: '4px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    marginBottom: '12px',
                    overflow: 'hidden',
                  }}
                >
                  {album.capa_url ? (
                    <img
                      src={album.capa_url}
                      alt={album.titulo}
                      style={{ width: '100%', height: '100%', objectFit: 'cover' }}
                    />
                  ) : (
                    <Disc size={48} color="#71717a" />
                  )}
                </div>

                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'flex-start',
                    gap: '8px',
                  }}
                >
                  <h3 style={{ margin: '0 0 4px 0' }}>{album.titulo}</h3>
                  {permiteGerenciar && (
                    <button
                      type="button"
                      onClick={() => handleExcluirAlbum(album.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#ef4444',
                        cursor: 'pointer',
                        padding: '4px',
                      }}
                      title="Excluir álbum"
                    >
                      <Trash2 size={16} />
                    </button>
                  )}
                </div>

                <p style={{ margin: '0 0 12px 0', fontSize: '0.85rem', color: '#a1a1aa' }}>
                  {album.genero} • {album.ano}
                  {album.artista_nome ? ` • ${album.artista_nome}` : ''}
                </p>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '12px' }}>
                  {album.musicas &&
                    album.musicas.map((musica) => {
                      const trackPayload: TrackPayload = {
                        id: musica.id,
                        titulo: musica.titulo,
                        artista: album.artista_nome || album.titulo,
                        url: musica.arquivo_url,
                        capa: album.capa_url,
                      };

                      return (
                        <div
                          key={musica.id}
                          style={{
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            padding: '6px 8px',
                            backgroundColor: '#27272a',
                            borderRadius: '4px',
                            gap: '8px',
                          }}
                        >
                          <span
                            style={{
                              fontSize: '0.9rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                              flex: 1,
                            }}
                          >
                            {musica.titulo}
                          </span>

                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <button
                              type="button"
                              onClick={() => onPlayTrack(trackPayload, albumTracks)}
                              style={{
                                background: 'none',
                                border: 'none',
                                color: '#ef4444',
                                cursor: 'pointer',
                              }}
                              title="Reproduzir faixa"
                            >
                              <Play size={18} />
                            </button>

                            {permiteGerenciar && (
                              <button
                                type="button"
                                onClick={() => handleExcluirMusica(musica.id)}
                                style={{
                                  background: 'none',
                                  border: 'none',
                                  color: '#f87171',
                                  cursor: 'pointer',
                                }}
                                title="Excluir faixa"
                              >
                                <Trash2 size={16} />
                              </button>
                            )}
                          </div>
                        </div>
                      );
                    })}
                </div>

                {tipoUsuario === 'artista' && (
                  <button
                    type="button"
                    onClick={() => {
                      setAlbumSelecionadoId(album.id);
                      setModalMusicaAberto(true);
                    }}
                    style={{
                      width: '100%',
                      padding: '8px',
                      backgroundColor: '#27272a',
                      color: '#fca5a5',
                      border: '1px dashed #ef4444',
                      borderRadius: '4px',
                      cursor: 'pointer',
                      fontSize: '0.8rem',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '6px',
                    }}
                  >
                    <Upload size={14} /> Adicionar Música (.mp3)
                  </button>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* MODAL CRIAR ÁLBUM */}
      {modalAlbumAberto && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 1000,
            padding: '16px',
          }}
        >
          <form
            onSubmit={handleCriarAlbum}
            style={{
              backgroundColor: '#18181b',
              padding: '24px',
              borderRadius: '8px',
              border: '1px solid #27272a',
              width: '100%',
              maxWidth: '400px',
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: '16px' }}>Cadastrar Novo Álbum</h3>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título do Álbum</label>
              <input
                type="text"
                value={tituloAlbum}
                onChange={(e) => setTituloAlbum(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Gênero Musical</label>
              <input
                type="text"
                value={generoAlbum}
                onChange={(e) => setGeneroAlbum(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Ano</label>
              <input
                type="number"
                value={anoAlbum}
                onChange={(e) => setAnoAlbum(Number(e.target.value))}
                required
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>URL da Capa (Opcional)</label>
              <input
                type="text"
                value={capaUrl}
                onChange={(e) => setCapaUrl(e.target.value)}
                placeholder="https://..."
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setModalAlbumAberto(false)}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#27272a',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                Cancelar
              </button>
              <button
                type="submit"
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#ef4444',
                  color: '#fff',
                  fontWeight: 'bold',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                Salvar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL UPLOAD DE MÚSICA */}
      {modalMusicaAberto && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 1000,
            padding: '16px',
          }}
        >
          <form
            onSubmit={handleUploadMusica}
            style={{
              backgroundColor: '#18181b',
              padding: '24px',
              borderRadius: '8px',
              border: '1px solid #27272a',
              width: '100%',
              maxWidth: '400px',
            }}
          >
            <h3 style={{ marginTop: 0, marginBottom: '16px' }}>Adicionar Música Local (.mp3)</h3>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título da Música</label>
              <input
                type="text"
                value={tituloMusica}
                onChange={(e) => setTituloMusica(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: '12px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Duração (segundos)</label>
              <input
                type="number"
                value={duracaoMusica}
                onChange={(e) => setDuracaoMusica(Number(e.target.value))}
                required
                style={{
                  width: '100%',
                  padding: '8px',
                  backgroundColor: '#27272a',
                  border: 'none',
                  borderRadius: '4px',
                  color: '#fff',
                  marginTop: '4px',
                  boxSizing: 'border-box',
                }}
              />
            </div>
            <div style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Arquivo de Áudio (.mp3, .wav)</label>
              <input
                type="file"
                accept="audio/*"
                onChange={(e) => setArquivoAudio(e.target.files ? e.target.files[0] : null)}
                required
                style={{ width: '100%', marginTop: '4px', color: '#fff' }}
              />
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                onClick={() => setModalMusicaAberto(false)}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#27272a',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                Cancelar
              </button>
              <button
                type="submit"
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#ef4444',
                  color: '#fff',
                  fontWeight: 'bold',
                  border: 'none',
                  borderRadius: '4px',
                  cursor: 'pointer',
                }}
              >
                Enviar Áudio
              </button>
            </div>
          </form>
        </div>
      )}

      {/* MODAL BUSCA GLOBAL */}
      {modalGlobalAberto && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0,0,0,0.8)',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            zIndex: 1000,
            padding: '16px',
          }}
        >
          <div
            style={{
              backgroundColor: '#18181b',
              padding: '24px',
              borderRadius: '8px',
              border: '1px solid #27272a',
              width: '100%',
              maxWidth: '640px',
              maxHeight: '80vh',
              display: 'flex',
              flexDirection: 'column',
              gap: '14px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h3 style={{ margin: 0 }}>Busca Global</h3>
              <button
                type="button"
                onClick={() => setModalGlobalAberto(false)}
                style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer' }}
              >
                <X size={20} />
              </button>
            </div>

            <form onSubmit={handleBuscaGlobal} style={{ display: 'flex', gap: '8px' }}>
              <input
                type="text"
                value={termoBusca}
                onChange={(e) => setTermoBusca(e.target.value)}
                placeholder="Buscar artista, álbum ou faixa..."
                style={{
                  flex: 1,
                  padding: '8px 12px',
                  backgroundColor: '#27272a',
                  border: '1px solid #3f3f46',
                  borderRadius: '6px',
                  color: '#fff',
                }}
              />
              <button
                type="submit"
                disabled={buscandoGlobal}
                style={{
                  padding: '8px 16px',
                  backgroundColor: '#ef4444',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  fontWeight: 'bold',
                  cursor: 'pointer',
                }}
              >
                {buscandoGlobal ? 'Buscando...' : 'Buscar'}
              </button>
            </form>

            <div style={{ overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {resultadosBusca.length === 0 ? (
                <p style={{ color: '#a1a1aa', fontSize: '0.85rem', margin: 0 }}>
                  Nenhum resultado exibido.
                </p>
              ) : (
                resultadosBusca.map((item: any, idx: number) => (
                  <div
                    key={item.id ?? idx}
                    style={{
                      padding: '10px 12px',
                      backgroundColor: '#27272a',
                      borderRadius: '6px',
                      fontSize: '0.85rem',
                    }}
                  >
                    <strong>{item.titulo || item.nome || 'Resultado'}</strong>
                    {item.artista ? ` • ${item.artista}` : ''}
                    {item.ano ? ` (${item.ano})` : ''}
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL LOGS ADMIN */}
      {modalLogsAberto && tipoUsuario === 'admin' && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            padding: '16px',
            zIndex: 1000,
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '820px',
              maxHeight: '80vh',
              backgroundColor: '#18181b',
              border: '1px solid #3f3f46',
              borderRadius: '8px',
              padding: '20px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ margin: 0, fontSize: '1.2rem' }}>Logs de Auditoria (Admin)</h2>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  type="button"
                  onClick={buscarLogsAdmin}
                  disabled={carregandoLogs}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    backgroundColor: '#27272a',
                    color: '#e4e4e7',
                    border: '1px solid #3f3f46',
                    padding: '6px 12px',
                    borderRadius: '6px',
                    cursor: 'pointer',
                    fontSize: '0.8rem',
                  }}
                >
                  <RefreshCw size={14} />
                  Atualizar
                </button>
                <button
                  type="button"
                  onClick={() => setModalLogsAberto(false)}
                  style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer' }}
                  title="Fechar"
                >
                  <X size={20} />
                </button>
              </div>
            </div>

            <div
              style={{
                backgroundColor: '#09090b',
                border: '1px solid #27272a',
                borderRadius: '6px',
                padding: '12px',
                overflowY: 'auto',
                fontFamily: 'monospace',
                fontSize: '0.8rem',
                lineHeight: 1.5,
                whiteSpace: 'pre-wrap',
                flex: 1,
              }}
            >
              {carregandoLogs
                ? 'Carregando logs...'
                : logsLinhas.length === 0
                ? 'Nenhum registro encontrado em auditoria.log.'
                : logsLinhas.join('\n')}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};