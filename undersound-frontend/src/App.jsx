// src/App.jsx

import { useState, useEffect } from 'react';
import axios from 'axios';

const API_URL = 'http://localhost:8000';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [userData, setUserData] = useState(null);
  const [artistName, setArtistName] = useState('');
  const [artistGenre, setArtistGenre] = useState('');
  const [message, setMessage] = useState('');

  // Efeito para buscar os dados do usuário automaticamente se houver um token
  useEffect(() => {
    if (token) {
      fetchUserData();
    }
  }, [token]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const formData = new URLSearchParams();
      formData.append('username', username);
      formData.append('password', password);

      const response = await axios.post(`${API_URL}/token`, formData, {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });

      const accessToken = response.data.access_token;
      setToken(accessToken);
      localStorage.setItem('token', accessToken);
      setMessage('Login bem-sucedido!');
      setUserData(null);
    } catch (error) {
      console.error('Erro no login:', error.response.data);
      setMessage('Erro no login: ' + (error.response?.data?.detail || 'Verifique suas credenciais.'));
      setToken('');
      localStorage.removeItem('token');
    }
  };

  const fetchUserData = async () => {
    try {
      const response = await axios.get(`${API_URL}/users/me`, {
        headers: {
          Authorization: `Bearer ${token}`
        }
      });
      setUserData(response.data);
      setMessage('Dados do usuário carregados com sucesso!');
    } catch (error) {
      console.error('Erro ao buscar dados do usuário:', error.response.data);
      setMessage('Erro ao buscar dados do usuário: ' + (error.response?.data?.detail || 'Você não está autenticado.'));
      setUserData(null);
    }
  };

  const handleCreateArtist = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API_URL}/artists/`, {
        name: artistName,
        genre: artistGenre
      });
      console.log('Artista criado:', response.data);
      setMessage(`Artista "${response.data.name}" criado com sucesso!`);
    } catch (error) {
      console.error('Erro ao criar artista:', error.response.data);
      setMessage('Erro ao criar artista: ' + (error.response?.data?.detail || 'Verifique os dados.'));
    }
  };

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif', maxWidth: '600px', margin: 'auto' }}>
      <h1>Undersound App</h1>
      <p style={{ color: message.includes('Erro') ? 'red' : 'green' }}>{message}</p>

      <hr style={{ margin: '20px 0' }} />

      <h2>Login</h2>
      <form onSubmit={handleLogin}>
        <div style={{ marginBottom: '10px' }}>
          <input
            type="text"
            placeholder="Nome de usuário"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <input
            type="password"
            placeholder="Senha"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <button type="submit" style={{ width: '100%', padding: '10px', backgroundColor: 'blue', color: 'white', border: 'none', cursor: 'pointer' }}>Entrar</button>
      </form>

      {token && (
        <>
          <hr style={{ margin: '20px 0' }} />
          <h2>Perfil do Usuário Logado</h2>
          <button onClick={fetchUserData} style={{ width: '100%', padding: '10px', backgroundColor: 'darkgreen', color: 'white', border: 'none', cursor: 'pointer' }}>Buscar Dados do Meu Perfil</button>
          {userData && (
            <div style={{ marginTop: '15px', backgroundColor: '#f0f0f0', padding: '15px', borderRadius: '5px' }}>
              <pre>{JSON.stringify(userData, null, 2)}</pre>
            </div>
          )}
        </>
      )}
      
      <hr style={{ margin: '20px 0' }} />
      <h2>Criar Artista</h2>
      <form onSubmit={handleCreateArtist}>
        <div style={{ marginBottom: '10px' }}>
          <input
            type="text"
            placeholder="Nome do Artista"
            value={artistName}
            onChange={(e) => setArtistName(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <div style={{ marginBottom: '10px' }}>
          <input
            type="text"
            placeholder="Gênero"
            value={artistGenre}
            onChange={(e) => setArtistGenre(e.target.value)}
            required
            style={{ width: '100%', padding: '8px' }}
          />
        </div>
        <button type="submit" style={{ width: '100%', padding: '10px', backgroundColor: 'orange', color: 'white', border: 'none', cursor: 'pointer' }}>Criar Artista</button>
      </form>
    </div>
  );
}

export default App;