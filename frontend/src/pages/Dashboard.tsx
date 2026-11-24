import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Disc, PlusCircle, ArrowLeft, Music, User, ShieldCheck, Filter, RotateCcw, BarChart3 } from 'lucide-react';

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
  const trimmed = path.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith('http://localhost:8000') || trimmed.startsWith('https://localhost:8000')) {
    return trimmed.replace(/^https?:\/\/localhost:8000/, API_BASE_URL);
  }
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed;
  }
  const normalizedPath = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  return `${API_BASE_URL}${normalizedPath}`;
};

const formatarDuracaoTotal = (totalSegundos: number): string => {
  const seg = Math.max(0, Math.floor(totalSegundos || 0));
  const horas = Math.floor(seg / 3600);
  const minutos = Math.floor((seg % 3600) / 60);
  const segundos = seg % 60;
  const segFormatado = segundos < 10 ? `0${segundos}` : `${segundos}`;

  if (horas > 0) {
    const minFormatado = minutos < 10 ? `0${minutos}` : `${minutos}`;
    return `${horas}:${minFormatado}:${segFormatado}`;
  }

  return `${minutos}:${segFormatado}`;
};

interface Musica {
  id: number;
  titulo: string;
  duracao_segundos: number;
  ordem?: number;
}

interface Album {
  id: number;
  titulo: string;
  ano: number;
  genero: string;
  capa_url: string;
  artista_id: number;
  musicas: Musica[];
}

export const Dashboard: React.FC = () => {
  const [usuario, setUsuario] = useState<any>(null);
  const [meusAlbuns, setMeusAlbuns] = useState<Album[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  const [filtroGenero, setFiltroGenero] = useState<string>('TODOS');
  const [filtroAno, setFiltroAno] = useState<string>('TODOS');
  const [ordenacao, setOrdenacao] = useState<string>('RECENTES');

  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('undersound_token');
    if (!token) {
      navigate('/login');
      return;
    }

    Promise.all([
      api.get('/auth/me'),
      api.get('/albuns')
    ])
      .then(([resUser, resAlbuns]) => {
        setUsuario(resUser.data);

        if (resUser.data.tipo_usuario === 'artista') {
          const albunsDoArtista = resAlbuns.data.filter(
            (album: Album) => album.artista_id === resUser.data.id
          );
          setMeusAlbuns(albunsDoArtista);
        } else {
          setMeusAlbuns(resAlbuns.data);
        }
      })
      .catch((err) => {
        console.error("Erro ao carregar dados do dashboard:", err);
      })
      .finally(() => setLoading(false));
  }, [navigate]);

  const generosDisponiveis = useMemo(() => {
    return Array.from(new Set(meusAlbuns.map((a) => a.genero).filter(Boolean))).sort();
  }, [meusAlbuns]);

  const anosDisponiveis = useMemo(() => {
    return Array.from(new Set(meusAlbuns.map((a) => String(a.ano)).filter(Boolean))).sort((a, b) => Number(b) - Number(a));
  }, [meusAlbuns]);

  const albunsFiltrados = useMemo(() => {
    return meusAlbuns
      .filter((album) => {
        const matchGenero = filtroGenero === 'TODOS' || album.genero === filtroGenero;
        const matchAno = filtroAno === 'TODOS' || String(album.ano) === filtroAno;
        return matchGenero && matchAno;
      })
      .sort((a, b) => {
        if (ordenacao === 'RECENTES') return b.id - a.id;
        if (ordenacao === 'ANTIGOS') return a.id - b.id;
        if (ordenacao === 'MAIS_FAIXAS') return (b.musicas?.length || 0) - (a.musicas?.length || 0);
        if (ordenacao === 'DURACAO') {
          const durA = (a.musicas || []).reduce((acc, m) => acc + (m.duracao_segundos || 0), 0);
          const durB = (b.musicas || []).reduce((acc, m) => acc + (m.duracao_segundos || 0), 0);
          return durB - durA;
        }
        return 0;
      });
  }, [meusAlbuns, filtroGenero, filtroAno, ordenacao]);

  const totalAlbunsFiltrados = albunsFiltrados.length;
  const totalFaixasFiltradas = useMemo(() => {
    return albunsFiltrados.reduce((acc, album) => acc + (album.musicas ? album.musicas.length : 0), 0);
  }, [albunsFiltrados]);

  const tempoTotalSegundos = useMemo(() => {
    return albunsFiltrados.reduce((acc, album) => {
      return acc + (album.musicas || []).reduce((sum, m) => sum + (m.duracao_segundos || 0), 0);
    }, 0);
  }, [albunsFiltrados]);

  const temFiltroAtivo = filtroGenero !== 'TODOS' || filtroAno !== 'TODOS' || ordenacao !== 'RECENTES';

  const limparFiltros = () => {
    setFiltroGenero('TODOS');
    setFiltroAno('TODOS');
    setOrdenacao('RECENTES');
  };

  if (loading) {
    return (
      <div style={{ padding: '40px', color: '#a1a1aa', backgroundColor: '#09090b', minHeight: '100vh', textAlign: 'center' }}>
        Carregando painel analítico do artista...
      </div>
    );
  }

  return (
    <div style={{ padding: '32px', color: '#fff', backgroundColor: '#09090b', minHeight: 'calc(100vh - 60px)', paddingBottom: '90px' }}>
      
      {/* Barra Superior do Dashboard */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <button 
            onClick={() => navigate('/')}
            style={{ 
              background: '#18181b', border: '1px solid #27272a', color: '#fff', 
              padding: '8px 12px', borderRadius: '6px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px',
              fontSize: '0.85rem'
            }}
          >
            <ArrowLeft size={16} /> Voltar ao Catálogo
          </button>
          <div>
            <h1 style={{ fontSize: '1.8rem', margin: 0 }}>Painel Analítico do Artista</h1>
            <p style={{ color: '#a1a1aa', fontSize: '0.85rem', margin: '4px 0 0 0' }}>
              Indicadores dinâmicos, filtragem de acervo e métricas de publicação
            </p>
          </div>
        </div>

        <button
          onClick={() => navigate('/')}
          style={{
            display: 'flex', alignItems: 'center', gap: '8px',
            backgroundColor: '#ef4444', color: '#fff', border: 'none',
            padding: '8px 16px', borderRadius: '6px', cursor: 'pointer',
            fontSize: '0.85rem', fontWeight: 'bold'
          }}
        >
          <PlusCircle size={16} /> Publicar Novo Álbum na Home
        </button>
      </div>

      {/* Barra de Filtros Dinâmicos do Dashboard */}
      <div style={{ 
        backgroundColor: '#18181b', 
        border: '1px solid #27272a', 
        padding: '16px 20px', 
        borderRadius: '8px', 
        marginBottom: '24px',
        display: 'flex',
        flexWrap: 'wrap',
        alignItems: 'center',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#ef4444', fontWeight: 'bold', fontSize: '0.9rem' }}>
          <Filter size={18} /> Filtros Analíticos:
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: '180px' }}>
          <label style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>Estilo Musical</label>
          <select
            value={filtroGenero}
            onChange={(e) => setFiltroGenero(e.target.value)}
            style={{
              backgroundColor: '#09090b',
              color: '#fff',
              border: '1px solid #3f3f46',
              borderRadius: '6px',
              padding: '8px 12px',
              fontSize: '0.85rem',
              cursor: 'pointer'
            }}
          >
            <option value="TODOS">Todos os Estilos</option>
            {generosDisponiveis.map((genero) => (
              <option key={genero} value={genero}>{genero}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: '160px' }}>
          <label style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>Ano de Lançamento</label>
          <select
            value={filtroAno}
            onChange={(e) => setFiltroAno(e.target.value)}
            style={{
              backgroundColor: '#09090b',
              color: '#fff',
              border: '1px solid #3f3f46',
              borderRadius: '6px',
              padding: '8px 12px',
              fontSize: '0.85rem',
              cursor: 'pointer'
            }}
          >
            <option value="TODOS">Todos os Períodos</option>
            {anosDisponiveis.map((ano) => (
              <option key={ano} value={ano}>{ano}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', minWidth: '210px' }}>
          <label style={{ fontSize: '0.75rem', color: '#a1a1aa' }}>Ordenar Acervo Por</label>
          <select
            value={ordenacao}
            onChange={(e) => setOrdenacao(e.target.value)}
            style={{
              backgroundColor: '#09090b',
              color: '#fff',
              border: '1px solid #3f3f46',
              borderRadius: '6px',
              padding: '8px 12px',
              fontSize: '0.85rem',
              cursor: 'pointer'
            }}
          >
            <option value="RECENTES">Data de Inclusão (Mais Recentes)</option>
            <option value="ANTIGOS">Data de Inclusão (Mais Antigos)</option>
            <option value="MAIS_FAIXAS">Maior Volume de Faixas</option>
            <option value="DURACAO">Maior Duração Total</option>
          </select>
        </div>

        {temFiltroAtivo && (
          <button
            onClick={limparFiltros}
            style={{
              marginTop: '18px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              backgroundColor: '#27272a',
              color: '#e4e4e7',
              border: '1px solid #3f3f46',
              padding: '8px 12px',
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '0.8rem'
            }}
          >
            <RotateCcw size={14} /> Limpar Filtros
          </button>
        )}
      </div>

      {/* Cards de Resumo / Estatísticas */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', marginBottom: '32px' }}>
        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <User size={16} color="#ef4444" /> Nome da Conta
          </div>
          <h3 style={{ margin: 0, fontSize: '1.15rem' }}>{usuario?.nome}</h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <ShieldCheck size={16} color="#ef4444" /> Tipo de Perfil
          </div>
          <h3 style={{ margin: 0, fontSize: '1.15rem', textTransform: 'uppercase', color: '#ef4444' }}>
            {usuario?.tipo_usuario}
          </h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <Disc size={16} color="#ef4444" /> Álbuns Filtrados
          </div>
          <h3 style={{ margin: 0, fontSize: '1.3rem' }}>
            {totalAlbunsFiltrados} <span style={{ fontSize: '0.8rem', color: '#71717a', fontWeight: 'normal' }}>/ {meusAlbuns.length} total</span>
          </h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <Music size={16} color="#ef4444" /> Faixas no Filtro
          </div>
          <h3 style={{ margin: 0, fontSize: '1.3rem' }}>{totalFaixasFiltradas}</h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <BarChart3 size={16} color="#ef4444" /> Tempo de Acervo
          </div>
          <h3 style={{ margin: 0, fontSize: '1.3rem' }}>{formatarDuracaoTotal(tempoTotalSegundos)}</h3>
        </div>
      </div>

      {/* Seção de Gerenciamento Rápido dos Álbuns Filtrados */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', borderBottom: '1px solid #27272a', paddingBottom: '8px' }}>
        <h2 style={{ fontSize: '1.3rem', margin: 0 }}>
          Seus Álbuns Cadastrados ({totalAlbunsFiltrados})
        </h2>
        {temFiltroAtivo && (
          <span style={{ fontSize: '0.8rem', color: '#ef4444' }}>
            Exibindo resultados filtrados
          </span>
        )}
      </div>

      {albunsFiltrados.length === 0 ? (
        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '32px', borderRadius: '8px', textAlign: 'center', color: '#a1a1aa' }}>
          {meusAlbuns.length === 0 ? (
            <>
              <p>Você ainda não publicou nenhum álbum.</p>
              <button 
                onClick={() => navigate('/')} 
                style={{ marginTop: '12px', background: '#ef4444', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
              >
                Publicar Primeiro Álbum
              </button>
            </>
          ) : (
            <>
              <p>Nenhum álbum encontrado com os filtros selecionados.</p>
              <button 
                onClick={limparFiltros} 
                style={{ marginTop: '12px', background: '#27272a', color: '#fff', border: '1px solid #3f3f46', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
              >
                Restaurar Todos os Álbuns
              </button>
            </>
          )}
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '20px' }}>
          {albunsFiltrados.map((album) => {
            const capaResolvida = resolverUrlMidia(album.capa_url);

            return (
              <div key={album.id} style={{ backgroundColor: '#18181b', borderRadius: '8px', border: '1px solid #27272a', padding: '16px' }}>
                <div style={{ width: '100%', height: '160px', backgroundColor: '#27272a', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px', overflow: 'hidden' }}>
                  {capaResolvida ? (
                    <img src={capaResolvida} alt={album.titulo} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                  ) : (
                    <Disc size={40} color="#71717a" />
                  )}
                </div>
                <h3 style={{ margin: '0 0 4px 0' }}>{album.titulo}</h3>
                <p style={{ margin: '0 0 12px 0', fontSize: '0.85rem', color: '#a1a1aa' }}>
                  {album.genero} • {album.ano} ({album.musicas?.length || 0} faixas)
                </p>
                
                <button
                  onClick={() => navigate('/')}
                  style={{
                    width: '100%', padding: '8px', backgroundColor: '#27272a', color: '#fff',
                    border: '1px solid #3f3f46', borderRadius: '4px', cursor: 'pointer', fontSize: '0.8rem',
                    fontWeight: 'bold'
                  }}
                >
                  Gerenciar na Home (Editar/Arrastar)
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};