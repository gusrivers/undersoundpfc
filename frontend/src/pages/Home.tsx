import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { Play, Disc } from 'lucide-react';

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
  musicas: Musica[];
}

interface HomeProps {
  onPlayTrack: (track: { titulo: string; artista: string; url: string }) => void;
}

export const Home: React.FC<HomeProps> = ({ onPlayTrack }) => {
  const [albuns, setAlbuns] = useState<Album[]>([]);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    api.get('/albuns')
      .then((res) => setAlbuns(res.data))
      .catch((err) => console.error(err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div style={{ padding: '32px', color: '#fff', backgroundColor: '#09090b', minHeight: 'calc(100vh - 60px)', pb: '90px' }}>
      <h1 style={{ marginBottom: '24px', fontSize: '1.8rem' }}>Catálogo Underground Local</h1>

      {loading ? (
        <p style={{ color: '#a1a1aa' }}>Carregando catálogo...</p>
      ) : albuns.length === 0 ? (
        <p style={{ color: '#a1a1aa' }}>Nenhum álbum cadastrado no momento.</p>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '24px' }}>
          {albuns.map((album) => (
            <div key={album.id} style={{ backgroundColor: '#18181b', borderRadius: '8px', border: '1px solid #27272a', padding: '16px' }}>
              <div style={{ width: '100%', height: '180px', backgroundColor: '#27272a', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '12px', overflow: 'hidden' }}>
                {album.capa_url ? (
                  <img src={album.capa_url} alt={album.titulo} style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <Disc size={48} color="#71717a" />
                )}
              </div>
              <h3 style={{ margin: '0 0 4px 0' }}>{album.titulo}</h3>
              <p style={{ margin: '0 0 12px 0', fontSize: '0.85rem', color: '#a1a1aa' }}>
                {album.genero} • {album.ano}
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {album.musicas.map((musica) => (
                  <div key={musica.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 8px', backgroundColor: '#27272a', borderRadius: '4px' }}>
                    <span style={{ fontSize: '0.9rem', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '180px' }}>
                      {musica.titulo}
                    </span>
                    <button onClick={() => onPlayTrack({ titulo: musica.titulo, artista: album.titulo, url: musica.arquivo_url })} style={{ background: 'none', border: 'none', color: '#22c55e', cursor: 'pointer' }}>
                      <Play size={18} />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};