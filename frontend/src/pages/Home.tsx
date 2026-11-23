import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Play, Disc, Trash2, FileText, X, RefreshCw } from 'lucide-react';

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

export const Home: React.FC<HomeProps> = ({ onPlayTrack, onResetPlayer }) => {
  const [albuns, setAlbuns] = useState<Album[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [estaLogado, setEstaLogado] = useState<boolean>(false);
  const [tipoUsuario, setTipoUsuario] = useState<string>('');
  const [usuarioIdLogado, setUsuarioIdLogado] = useState<number | null>(null);

  // Estados do painel de logs para o admin
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
      setTipoUsuario('');
      setUsuarioIdLogado(null);
      return;
    }

    setEstaLogado(true);
    try {
      const res = await api.get('/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      });
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
    return tipoUsuario === 'artista' && album.artista_id != null && album.artista_id === usuarioIdLogado;
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
        headers: {
          Authorization: `Bearer ${token}`,
        },
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
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '24px',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <h1 style={{ fontSize: '1.8rem', margin: 0 }}>Catálogo Underground Local</h1>
          {estaLogado && tipoUsuario && (
            <p style={{ color: '#a1a1aa', fontSize: '0.85rem', margin: '4px 0 0 0' }}>
              Perfil logado:{' '}
              <strong style={{ color: tipoUsuario === 'admin' ? '#f59e0b' : '#22c55e' }}>
                {tipoUsuario.toUpperCase()}
              </strong>
            </p>
          )}
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          {tipoUsuario === 'admin' && (
            <button
              onClick={handleAbrirLogs}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: '#451a03',
                color: '#fcd34d',
                border: '1px solid #92400e',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 'bold',
              }}
              title="Visualizar logs de auditoria do sistema"
            >
              <FileText size={16} />
              Ver Logs (Admin)
            </button>
          )}

          {estaLogado && (
            <button
              onClick={handleExcluirConta}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                backgroundColor: '#450a0a',
                color: '#fca5a5',
                border: '1px solid #7f1d1d',
                padding: '8px 16px',
                borderRadius: '6px',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontWeight: 'bold',
              }}
              title="Excluir minha conta e dados (LGPD - RF06)"
            >
              <Trash2 size={16} />
              Excluir Minha Conta (LGPD)
            </button>
          )}
        </div>
      </div>

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
                      onClick={() => handleExcluirAlbum(album.id)}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: '#f87171',
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

                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
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
                              onClick={() => onPlayTrack(trackPayload, albumTracks)}
                              style={{
                                background: 'none',
                                border: 'none',
                                color: '#22c55e',
                                cursor: 'pointer',
                              }}
                              title="Reproduzir faixa"
                            >
                              <Play size={18} />
                            </button>

                            {permiteGerenciar && (
                              <button
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
              </div>
            );
          })}
        </div>
      )}

      {/* Modal de Logs exclusivo para Admin */}
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
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <h2 style={{ margin: 0, fontSize: '1.2rem' }}>Logs de Auditoria (Admin)</h2>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
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
                  onClick={() => setModalLogsAberto(false)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#a1a1aa',
                    cursor: 'pointer',
                  }}
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
              {carregandoLogs ? (
                'Carregando logs...'
              ) : logsLinhas.length === 0 ? (
                'Nenhum registro encontrado em auditoria.log.'
              ) : (
                logsLinhas.join('\n')
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};