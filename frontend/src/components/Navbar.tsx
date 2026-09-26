import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Disc, LogOut, PlusCircle, Home } from 'lucide-react';

export const Navbar: React.FC = () => {
  const navigate = useNavigate();
  const token = localStorage.getItem('undersound_token');

  const handleLogout = () => {
    localStorage.removeItem('undersound_token');
    navigate('/login');
  };

  return (
    <nav style={{
      height: '60px', backgroundColor: '#18181b', borderBottom: '1px solid #27272a',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      padding: '0 32px', color: '#fff'
    }}>
      <Link to="/" style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#22c55e', textDecoration: 'none', fontWeight: 'bold', fontSize: '1.2rem' }}>
        <Disc size={28} /> UNDERSOUND
      </Link>

      <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
        <Link to="/" style={{ color: '#f4f4f5', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <Home size={18} /> Início
        </Link>
        {token && (
          <Link to="/cadastro-musica" style={{ color: '#f4f4f5', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <PlusCircle size={18} /> Cadastrar Música
          </Link>
        )}
        {token ? (
          <button onClick={handleLogout} style={{
            background: 'none', border: '1px solid #3f3f46', color: '#ef4444',
            padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px'
          }}>
            <LogOut size={16} /> Sair
          </button>
        ) : (
          <Link to="/login" style={{ backgroundColor: '#22c55e', color: '#000', textDecoration: 'none', padding: '6px 16px', borderRadius: '4px', fontWeight: 'bold' }}>
            Entrar
          </Link>
        )}
      </div>
    </nav>
  );
};