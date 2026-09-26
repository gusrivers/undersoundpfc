import React, { useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Navbar } from './components/Navbar';
import { AudioPlayer } from './components/AudioPlayer';
import { Home } from './pages/Home';
import { Login } from './pages/Login';
import { CadastroMusica } from './pages/CadastroMusica';

export const App: React.FC = () => {
  const [currentTrack, setCurrentTrack] = useState<{ titulo: string; artista: string; url: string } | null>(null);

  return (
    <BrowserRouter>
      <div style={{ backgroundColor: '#09090b', minHeight: '100vh', fontFamily: 'sans-serif' }}>
        <Navbar />
        <Routes>
          <Route path="/" element={<Home onPlayTrack={setCurrentTrack} />} />
          <Route path="/login" element={<Login />} />
          <Route path="/cadastro-musica" element={<CadastroMusica />} />
        </Routes>
        <AudioPlayer currentTrack={currentTrack} />
      </div>
    </BrowserRouter>
  );
};

export default App;