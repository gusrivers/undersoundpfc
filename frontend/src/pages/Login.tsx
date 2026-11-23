import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { LgpdModal } from '../components/LgpdModal';
import { CheckCircle2} from 'lucide-react';

export const Login: React.FC = () => {
  const [isCadastro, setIsCadastro] = useState(false);
  const [nome, setNome] = useState('');
  const [email, setEmail] = useState('');
  const [senha, setSenha] = useState('');
  const [tipoUsuario, setTipoUsuario] = useState('ouvinte');
  const [aceitouLgpd, setAceitouLgpd] = useState(false);
  const [modalLgpdAberto, setModalLgpdAberto] = useState(false);
  const [erro, setErro] = useState('');
  const [sucesso, setSucesso] = useState('');

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErro('');
    setSucesso('');

    try {
      if (isCadastro) {
        if (!aceitouLgpd) {
          setErro('Você precisa aceitar os Termos de Uso (LGPD) para prosseguir.');
          return;
        }
        await api.post('/auth/cadastro', {
          nome, email, senha, tipo_usuario: tipoUsuario, aceitou_termos_lgpd: aceitouLgpd
        });
        
        setSucesso('Cadastro realizado com sucesso! Insira sua senha para entrar.');
        setSenha('');
        setIsCadastro(false);
      } else {
        const response = await api.post('/auth/login', { email, senha });
        localStorage.setItem('undersound_token', response.data.access_token);
        navigate('/');
      }
    } catch (err: any) {
      setErro(err.response?.data?.detail || 'Erro na operação. Verifique seus dados.');
    }
  };

  return (
    <div style={{ 
      display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', 
      minHeight: '100vh', backgroundColor: '#09090b', color: '#fff', padding: '20px' 
    }}>
      
      {/* LOGO DA MARCA */}
      <div style={{ textAlign: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginBottom: '8px' }}>
          {/* Ondas Sonoras Estilizadas */}
          <div style={{ width: '4px', height: '16px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          <div style={{ width: '4px', height: '24px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          <div style={{ width: '4px', height: '32px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          <div style={{ width: '6px', height: '42px', backgroundColor: '#fff', borderRadius: '3px' }}></div>
          <div style={{ width: '4px', height: '32px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          <div style={{ width: '4px', height: '24px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
          <div style={{ width: '4px', height: '16px', backgroundColor: '#ef4444', borderRadius: '2px' }}></div>
        </div>
        <h1 style={{ fontSize: '1.6rem', fontWeight: '900', letterSpacing: '2px', margin: 0, color: '#fff' }}>
          UNDERSOUND
        </h1>
        <p style={{ fontSize: '0.75rem', color: '#a1a1aa', margin: '4px 0 0 0', letterSpacing: '1px', textTransform: 'uppercase' }}>
          Streaming de Música Independente
        </p>
      </div>

      {/* FORMULÁRIO DE AUTENTICAÇÃO */}
      <form onSubmit={handleSubmit} style={{ backgroundColor: '#18181b', padding: '32px', borderRadius: '12px', border: '1px solid #27272a', width: '100%', maxWidth: '400px', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)' }}>
        <h2 style={{ margin: '0 0 20px 0', textAlign: 'center', fontSize: '1.2rem', color: '#e4e4e7' }}>
          {isCadastro ? 'Criar Nova Conta' : 'Acessar Plataforma'}
        </h2>
        
        {erro && (
          <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', border: '1px solid #7f1d1d', padding: '10px 12px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.85rem' }}>
            {erro}
          </div>
        )}

        {sucesso && (
          <div style={{ 
            backgroundColor: 'rgba(20, 83, 45, 0.4)', 
            color: '#86efac', 
            border: '1px solid #166534', 
            padding: '10px 12px', 
            borderRadius: '6px', 
            marginBottom: '16px', 
            fontSize: '0.85rem',
            display: 'flex',
            alignItems: 'center',
            gap: '8px'
          }}>
            <CheckCircle2 size={18} color="#22c55e" style={{ flexShrink: 0 }} />
            <span>{sucesso}</span>
          </div>
        )}

        {isCadastro && (
          <div style={{ marginBottom: '16px' }}>
            <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Nome Completo / Banda</label>
            <input type="text" value={nome} onChange={(e) => setNome(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
          </div>
        )}

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>E-mail</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Senha</label>
          <input type="password" value={senha} onChange={(e) => setSenha(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }} />
        </div>

        {isCadastro && (
          <>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Tipo de Perfil</label>
              <select value={tipoUsuario} onChange={(e) => setTipoUsuario(e.target.value)} style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: '1px solid #3f3f46', borderRadius: '6px', color: '#fff', marginTop: '4px', outline: 'none' }}>
                <option value="ouvinte">Ouvinte / Fã</option>
                <option value="artista">Artista / Banda Independentes</option>
              </select>
            </div>

            <div style={{ marginBottom: '20px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <input type="checkbox" id="lgpd" checked={aceitouLgpd} onChange={(e) => setAceitouLgpd(e.target.checked)} style={{ accentColor: '#ef4444', cursor: 'pointer', width: '16px', height: '16px' }} />
              <label htmlFor="lgpd" style={{ cursor: 'pointer', color: '#d4d4d8' }}>
                Li e aceito os{' '}
                <span onClick={(e) => { e.preventDefault(); setModalLgpdAberto(true); }} style={{ color: '#ef4444', textDecoration: 'underline', cursor: 'pointer', fontWeight: 'bold' }}>
                  Termos de Uso e Privacidade (LGPD)
                </span>
              </label>
            </div>
          </>
        )}

        <button type="submit" style={{ width: '100%', padding: '12px', backgroundColor: '#ef4444', color: '#fff', fontWeight: 'bold', border: 'none', borderRadius: '6px', cursor: 'pointer', fontSize: '0.95rem', transition: 'background-color 0.2s' }}>
          {isCadastro ? 'Cadastrar Conta' : 'Entrar'}
        </button>

        <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '0.85rem', color: '#a1a1aa' }}>
          {isCadastro ? 'Já possui conta?' : 'Não tem conta?'}{' '}
          <span 
            onClick={() => { 
              setIsCadastro(!isCadastro); 
              setErro(''); 
              setSucesso(''); 
            }} 
            style={{ color: '#ef4444', cursor: 'pointer', textDecoration: 'underline', fontWeight: 'bold' }}
          >
            {isCadastro ? 'Faça Login' : 'Cadastre-se'}
          </span>
        </p>
      </form>

      <LgpdModal isOpen={modalLgpdAberto} onClose={() => setModalLgpdAberto(false)} />
    </div>
  );
};