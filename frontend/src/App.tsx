import React, { useState, useRef, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Login } from './pages/Login';
import { Home } from './pages/Home';
import { Dashboard } from './pages/Dashboard';
import { Disc, Play, Pause, SkipBack, SkipForward, Volume2 } from 'lucide-react';


const RotaPrivada = ({ children }: { children: JSX.Element }) => {
  const token = localStorage.getItem('undersound_token');
  return token ? children : <Navigate to="/login" replace />;
};

interface Track {
  id: number;
  titulo: string;
  artista: string;
  url: string;
  capa?: string;
}

export function App() {
  const [currentTrack, setCurrentTrack] = useState<Track | null>(null);
  const [playlist, setPlaylist] = useState<Track[]>([]);
  const [currentIndex, setCurrentIndex] = useState<number>(0);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [progress, setProgress] = useState<number>(0);
  const [duration, setDuration] = useState<number>(0);

  const audioRef = useRef<HTMLAudioElement | null>(null);

  // Função chamada ao clicar em play em alguma música
  const handlePlayTrack = (track: Track, albumTracks: Track[] = []) => {
    setCurrentTrack(track);
    setPlaylist(albumTracks);
    const index = albumTracks.findIndex(t => t.id === track.id);
    setCurrentIndex(index !== -1 ? index : 0);
    setIsPlaying(true);
  };

  useEffect(() => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.play().catch(err => console.log("Erro ao reproduzir:", err));
      } else {
        audioRef.current.pause();
      }
    }
  }, [currentTrack, isPlaying]);

  // Avançar para a próxima música automaticamente ou pelo botão
  const handleNext = () => {
    if (playlist.length > 0 && currentIndex < playlist.length - 1) {
      const nextIndex = currentIndex + 1;
      setCurrentIndex(nextIndex);
      setCurrentTrack(playlist[nextIndex]);
      setIsPlaying(true);

      if (audioRef.current) {
        audioRef.current.load();
        audioRef.current.play().catch(err => console.log("Erro ao reproduzir:", err));
      }
    } else {
      setIsPlaying(false);
    }
  };

  // Voltar para a música anterior
  const handlePrev = () => {
    if (playlist.length > 0 && currentIndex > 0) {
      const prevIndex = currentIndex - 1;
      setCurrentIndex(prevIndex);
      setCurrentTrack(playlist[prevIndex]);
      setIsPlaying(true);

      if (audioRef.current) {
        audioRef.current.load();
        audioRef.current.play().catch(err => console.log("Erro ao reproduzir:", err));
      }
    }
  };

  const togglePlay = () => {
    if (!currentTrack) return;
    setIsPlaying(!isPlaying);
  };

  const handleTimeUpdate = () => {
    if (audioRef.current) {
      setProgress(audioRef.current.currentTime);
      setDuration(audioRef.current.duration || 0);
    }
  };

  const handleSeek = (e: React.ChangeEvent<HTMLInputElement>) => {
    const time = Number(e.target.value);
    if (audioRef.current) {
      audioRef.current.currentTime = time;
      setProgress(time);
    }
  };

  const formatTime = (seconds: number) => {
    if (isNaN(seconds)) return "0:00";
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}:${secs < 10 ? '0' : ''}${secs}`;
  };

  return (
    <BrowserRouter>
      <div style={{ minHeight: '100vh', backgroundColor: '#09090b', position: 'relative', paddingBottom: '100px' }}>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route 
            path="/" 
            element={
              <RotaPrivada>
                <Home onPlayTrack={handlePlayTrack} />
              </RotaPrivada>
            } 
          />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="*" element={<Navigate to="/login" replace />} />
        </Routes>

        {/* Elemento de Áudio Oculto com 'key' para forçar a troca correta da URL */}
        {currentTrack && (
          <audio
            ref={audioRef}
            key={currentTrack.url}
            src={currentTrack.url.startsWith('http') ? currentTrack.url : `http://localhost:8000${currentTrack.url}`}
            onTimeUpdate={handleTimeUpdate}
            onEnded={handleNext}
            autoPlay
          />
        )}

        {/* Player Fixo Personalizado */}
        {currentTrack && (
          <div style={{ 
            position: 'fixed', 
            bottom: 0, 
            left: 0, 
            width: '100vw', 
            backgroundColor: '#121216', 
            borderTop: '1px solid #27272a', 
            padding: '12px 24px', 
            display: 'flex', 
            alignItems: 'center', 
            justifyContent: 'space-between', 
            zIndex: 9999, 
            color: '#fff',
            boxShadow: '0 -4px 20px rgba(0,0,0,0.6)',
            boxSizing: 'border-box'
          }}>
            {/* Info da Música e Capa */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '14px', width: '30%' }}>
              <div style={{ width: '52px', height: '52px', backgroundColor: '#27272a', borderRadius: '6px', overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                {currentTrack.capa ? (
                  <img src={currentTrack.capa.startsWith('http') ? currentTrack.capa : `http://localhost:8000${currentTrack.capa}`} alt="Capa" style={{ width: '100%', height: '100%', objectFit: 'cover' }} />
                ) : (
                  <Disc size={26} color="#71717a" />
                )}
              </div>
              <div style={{ overflow: 'hidden' }}>
                <div style={{ fontSize: '0.9rem', fontWeight: 'bold', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden' }}>
                  {currentTrack.titulo}
                </div>
                <div style={{ fontSize: '0.75rem', color: '#a1a1aa', whiteSpace: 'nowrap', textOverflow: 'ellipsis', overflow: 'hidden', marginTop: '2px' }}>
                  {currentTrack.artista}
                </div>
              </div>
            </div>

            {/* Controles Centrais Personalizados */}
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', width: '40%' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
                <button 
                  onClick={handlePrev} 
                  style={{ background: 'none', border: 'none', color: currentIndex > 0 ? '#fff' : '#52525b', cursor: currentIndex > 0 ? 'pointer' : 'default' }}
                  title="Anterior"
                >
                  <SkipBack size={20} />
                </button>

                <button 
                  onClick={togglePlay} 
                  style={{ width: '36px', height: '36px', borderRadius: '50%', backgroundColor: '#ef4444', border: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer', color: '#000' }}
                  title={isPlaying ? "Pausar" : "Reproduzir"}
                >
                  {isPlaying ? <Pause size={18} fill="#000" /> : <Play size={18} fill="#000" style={{ marginLeft: '2px' }} />}
                </button>

                <button 
                  onClick={handleNext} 
                  style={{ background: 'none', border: 'none', color: playlist.length > 0 && currentIndex < playlist.length - 1 ? '#fff' : '#52525b', cursor: 'pointer' }}
                  title="Próxima"
                >
                  <SkipForward size={20} />
                </button>
              </div>

              {/* Barra de Progresso Customizada */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', width: '100%', maxWidth: '450px' }}>
                <span style={{ fontSize: '0.7rem', color: '#a1a1aa', minWidth: '35px', textAlign: 'right' }}>{formatTime(progress)}</span>
                <input 
                  type="range" 
                  min={0} 
                  max={duration || 100} 
                  value={progress} 
                  onChange={handleSeek}
                  style={{ flex: 1, accentColor: '#ef4444', cursor: 'pointer', height: '4px' }}
                />
                <span style={{ fontSize: '0.7rem', color: '#a1a1aa', minWidth: '35px' }}>{formatTime(duration)}</span>
              </div>
            </div>

            {/* Espaço Lateral Direito (Volume / Extras) */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '8px', width: '30%', color: '#a1a1aa' }}>
              <Volume2 size={18} />
              <span style={{ fontSize: '0.75rem' }}>Áudio Local</span>
            </div>
          </div>
        )}
      </div>
    </BrowserRouter>
  );
}

export default App;