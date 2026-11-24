import React, { useRef, useState, useEffect } from 'react';
import { Play, Pause, Volume2, Music } from 'lucide-react';

interface AudioPlayerProps {
  currentTrack: {
    titulo: string;
    artista: string;
    url: string;
  } | null;
}

export const AudioPlayer: React.FC<AudioPlayerProps> = ({ currentTrack }) => {
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);

  useEffect(() => {
    if (currentTrack && audioRef.current) {
      audioRef.current.play();
      setIsPlaying(true);
    }
  }, [currentTrack]);

  const togglePlay = () => {
    if (!audioRef.current) return;
    if (isPlaying) {
      audioRef.current.pause();
    } else {
      audioRef.current.play();
    }
    setIsPlaying(!isPlaying);
  };

  if (!currentTrack) return null;

  return (
    <div style={{
      position: 'fixed', bottom: 0, left: 0, right: 0,
      height: '70px', backgroundColor: '#09090b', borderTop: '1px solid #27272a',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 24px', color: '#fff', zIndex: 999
    }}>
      <audio ref={audioRef} src={currentTrack.url} onEnded={() => setIsPlaying(false)} />
      
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div style={{ width: '40px', height: '40px', backgroundColor: '#27272a', borderRadius: '4px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <Music size={20} color="#a1a1aa" />
        </div>
        <div>
          <div style={{ fontWeight: 'bold', fontSize: '0.95rem' }}>{currentTrack.titulo}</div>
          <div style={{ fontSize: '0.8rem', color: '#a1a1aa' }}>{currentTrack.artista}</div>
        </div>
      </div>

      <button onClick={togglePlay} style={{
        backgroundColor: '#f4f4f5', color: '#000', border: 'none',
        borderRadius: '50%', width: '44px', height: '44px',
        display: 'flex', alignItems: 'center', justifyContent: 'center', cursor: 'pointer'
      }}>
        {isPlaying ? <Pause size={20} /> : <Play size={20} style={{ marginLeft: '2px' }} />}
      </button>

      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#a1a1aa' }}>
        <Volume2 size={18} />
      </div>
    </div>
  );
};