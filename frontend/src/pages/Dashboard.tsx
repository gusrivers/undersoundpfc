import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { Disc, PlusCircle, Trash2, ArrowLeft, Music, User, ShieldCheck } from 'lucide-react';

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
  
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('undersound_token');
    if (!token) {
      navigate('/login');
      return;
    }

    // Busca dados do usuário logado e álbuns em paralelo
    Promise.all([
      api.get('/auth/me', { headers: { Authorization: `Bearer ${token}` } }),
      api.get('/albuns')
    ])
      .then(([resUser, resAlbuns]) => {
        setUsuario(resUser.data);
        
        // Se for artista, filtra apenas os álbuns dele
        if (resUser.data.tipo_usuario === 'artista') {
          const albunsDoArtista = resAlbuns.data.filter(
            (album: Album) => album.artista_id === resUser.data.id
          );
          setMeusAlbuns(albunsDoArtista);
        } else {
          // Se for ouvinte, pode ver todos ou uma mensagem restrita
          setMeusAlbuns(resAlbuns.data);
        }
      })
      .catch((err) => {
        console.error("Erro ao carregar dados do dashboard:", err);
      })
      .finally(() => setLoading(false));
  }, [navigate]);

  if (loading) {
    return (
      <div style={{ padding: '40px', color: '#a1a1aa', backgroundColor: '#09090b', minHeight: '100vh', textAlign: 'center' }}>
        Carregando painel do artista...
      </div>
    );
  }

  return (
    <div style={{ padding: '32px', color: '#fff', backgroundColor: '#09090b', minHeight: 'calc(100vh - 60px)', paddingBottom: '90px' }}>
      
      {/* Barra Superior do Dashboard */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '16px' }}>
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
            <h1 style={{ fontSize: '1.8rem', margin: 0 }}>Painel do Artista</h1>
            <p style={{ color: '#a1a1aa', fontSize: '0.85rem', margin: '4px 0 0 0' }}>
              Gerenciamento exclusivo de acervo e perfil independente
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

      {/* Cards de Resumo / Estatísticas */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '32px' }}>
        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <User size={16} color="#ef4444" /> Nome da Conta
          </div>
          <h3 style={{ margin: 0, fontSize: '1.2rem' }}>{usuario?.nome}</h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <ShieldCheck size={16} color="#ef4444" /> Tipo de Perfil
          </div>
          <h3 style={{ margin: 0, fontSize: '1.2rem', textTransform: 'uppercase', color: '#ef4444' }}>
            {usuario?.tipo_usuario}
          </h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <Disc size={16} color="#ef4444" /> Álbuns Publicados
          </div>
          <h3 style={{ margin: 0, fontSize: '1.2rem' }}>{meusAlbuns.length}</h3>
        </div>

        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '20px', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa', fontSize: '0.85rem', marginBottom: '8px' }}>
            <Music size={16} color="#ef4444" /> Total de Faixas
          </div>
          <h3 style={{ margin: 0, fontSize: '1.2rem' }}>
            {meusAlbuns.reduce((acc, album) => acc + (album.musicas ? album.musicas.length : 0), 0)}
          </h3>
        </div>
      </div>

      {/* Seção de Gerenciamento Rápido dos Álbuns do Artista */}
      <h2 style={{ fontSize: '1.3rem', marginBottom: '16px', borderBottom: '1px solid #27272a', paddingBottom: '8px' }}>
        Seus Álbuns Cadastrados
      </h2>

      {meusAlbuns.length === 0 ? (
        <div style={{ backgroundColor: '#18181b', border: '1px solid #27272a', padding: '32px', borderRadius: '8px', textAlign: 'center', color: '#a1a1aa' }}>
          <p>Você ainda não publicou nenhum álbum.</p>
          <button 
            onClick={() => navigate('/')} 
            style={{ marginTop: '12px', background: '#ef4444', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
          >
            Publicar Primeiro Álbum
          </button>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '20px' }}>
          {meusAlbuns.map((album) => (
            <div key={album.id} style={{ backgroundColor: '#18181b', borderRadius: '8px', border: '1px solid #27272a', padding: '16px' }}>
              <div style={{ width: '100%', height: '160px', backgroundColor: '#27272a', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px', overflow: 'hidden' }}>
                {album.capa_url ? (
                  <img src={album.capa_url.startsWith('http') ? album.capa_url : `http://localhost:8000${album.capa_url}`} alt={album.titulo} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
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
          ))}
        </div>
      )}
    </div>
  );
};