import React, { useState } from 'react';
import { api } from '../services/api';
import { Search, Plus } from 'lucide-react';

export const CadastroMusica: React.FC = () => {
  const [tituloAlbum, setTituloAlbum] = useState('');
  const [ano, setAno] = useState('2026');
  const [genero, setGenero] = useState('');
  const [tituloMusica, setTituloMusica] = useState('');
  const [urlMusica, setUrlMusica] = useState('');

  // Estados da API Externa (MusicBrainz)
  const [buscaArtista, setBuscaArtista] = useState('');
  const [resultadoExterno, setResultadoExterno] = useState<any>(null);

  const handleConsultarMusicBrainz = async () => {
    if (!buscaArtista) return;
    try {
      const res = await api.get(`/albuns/consulta-externa/${buscaArtista}`);
      setResultadoExterno(res.data);
    } catch (err) {
      alert('Erro ao consultar MusicBrainz.');
    }
  };

  const handleCadastrar = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const albumRes = await api.post('/albuns/', {
        titulo: tituloAlbum, ano: parseInt(ano), genero, capa_url: ''
      });
      
      await api.post(`/albuns/${albumRes.data.id}/musicas`, {
        titulo: tituloMusica, duracao_segundos: 180, arquivo_url: urlMusica
      });

      alert('Álbum e faixa cadastrados com sucesso!');
      setTituloAlbum(''); setGenero(''); setTituloMusica(''); setUrlMusica('');
    } catch (err: any) {
      alert('Erro ao salvar no banco. Verifique seu login.');
    }
  };

  return (
    <div style={{ padding: '32px', color: '#fff', backgroundColor: '#09090b', minHeight: 'calc(100vh - 60px)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px' }}>
      
      {/* Formulário da Regra de Negócio */}
      <form onSubmit={handleCadastrar} style={{ backgroundColor: '#18181b', padding: '24px', borderRadius: '8px', border: '1px solid #27272a' }}>
        <h2><Plus size={20} inline /> Publicar Nova Faixa / Álbum</h2>
        
        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Título do Álbum / EP</label>
          <input type="text" value={tituloAlbum} onChange={(e) => setTituloAlbum(e.target.value)} required style={{ width: '100%', padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
          <div>
            <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Ano</label>
            <input type="number" value={ano} onChange={(e) => setAno(e.target.value)} required style={{ width: '100%', padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
          </div>
          <div>
            <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Gênero</label>
            <input type="text" value={genero} onChange={(e) => setGenero(e.target.value)} required style={{ width: '100%', padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
          </div>
        </div>

        <div style={{ marginBottom: '12px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Nome da Música</label>
          <input type="text" value={tituloMusica} onChange={(e) => setTituloMusica(e.target.value)} required style={{ width: '100%', padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
        </div>

        <div style={{ marginBottom: '20px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>URL do Arquivo de Áudio (.mp3)</label>
          <input type="text" value={urlMusica} onChange={(e) => setUrlMusica(e.target.value)} placeholder="https://exemplo.com/faixa.mp3" required style={{ width: '100%', padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
        </div>

        <button type="submit" style={{ width: '100%', padding: '10px', backgroundColor: '#22c55e', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
          Salvar Mídia
        </button>
      </form>

      {/* Consulta de API Externa (MusicBrainz) */}
      <div style={{ backgroundColor: '#18181b', padding: '24px', borderRadius: '8px', border: '1px solid #27272a' }}>
        <h2><Search size={20} inline /> Integração Externa (MusicBrainz)</h2>
        <p style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Consulte a base de dados pública do MusicBrainz para validar informações de referência.</p>
        
        <div style={{ display: 'flex', gap: '8px', marginBottom: '16px' }}>
          <input type="text" value={buscaArtista} onChange={(e) => setBuscaArtista(e.target.value)} placeholder="Digite o nome de uma banda..." style={{ flex: 1, padding: '8px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff' }} />
          <button onClick={handleConsultarMusicBrainz} style={{ padding: '8px 16px', backgroundColor: '#3f3f46', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
            Buscar
          </button>
        </div>

        {resultadoExterno && (
          <div style={{ backgroundColor: '#27272a', padding: '12px', borderRadius: '4px', fontSize: '0.9rem' }}>
            <p><strong>Nome:</strong> {resultadoExterno.nome}</p>
            <p><strong>País:</strong> {resultadoExterno.pais}</p>
            <p><strong>Tipo:</strong> {resultadoExterno.tipo}</p>
            <p><strong>Detalhes:</strong> {resultadoExterno.disambiguation || 'Sem detalhes adicionais.'}</p>
          </div>
        )}
      </div>

    </div>
  );
};