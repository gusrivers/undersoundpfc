import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { LgpdModal } from '../components/LgpdModal';
import { Lock, Mail, User, ShieldCheck } from 'lucide-react';

export const Login: React.FC = () => {
  const [isCadastro, setIsCadastro] = useState(false);
  const [nome, setNome] = useState('');
  const [email, setEmail] = useState('');
  const [senha, setSenha] = useState('');
  const [tipoUsuario, setTipoUsuario] = useState('ouvinte');
  const [aceitouLgpd, setAceitouLgpd] = useState(false);
  const [modalLgpdAberto, setModalLgpdAberto] = useState(false);
  const [erro, setErro] = useState('');

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErro('');

    try {
      if (isCadastro) {
        if (!aceitouLgpd) {
          setErro('Você precisa aceitar os Termos de Uso (LGPD) para prosseguir.');
          return;
        }
        await api.post('/auth/cadastro', {
          nome, email, senha, tipo_usuario: tipoUsuario, aceitou_termos_lgpd: aceitouLgpd
        });
        alert('Cadastro realizado com sucesso! Faça login.');
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
    <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: 'calc(100vh - 60px)', backgroundColor: '#09090b', color: '#fff' }}>
      <form onSubmit={handleSubmit} style={{ backgroundColor: '#18181b', padding: '32px', borderRadius: '8px', border: '1px solid #27272a', width: '100%', maxWidth: '400px' }}>
        <h2 style={{ margin: '0 0 20px 0', textAlign: 'center' }}>{isCadastro ? 'Criar Conta' : 'Acessar Undersound'}</h2>
        
        {erro && <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px', borderRadius: '4px', marginBottom: '16px', fontSize: '0.85rem' }}>{erro}</div>}

        {isCadastro && (
          <div style={{ marginBottom: '16px' }}>
            <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Nome Completo / Banda</label>
            <input type="text" value={nome} onChange={(e) => setNome(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff', marginTop: '4px' }} />
          </div>
        )}

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>E-mail</label>
          <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff', marginTop: '4px' }} />
        </div>

        <div style={{ marginBottom: '16px' }}>
          <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Senha</label>
          <input type="password" value={senha} onChange={(e) => setSenha(e.target.value)} required style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff', marginTop: '4px' }} />
        </div>

        {isCadastro && (
          <>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '0.85rem', color: '#a1a1aa' }}>Tipo de Perfil</label>
              <select value={tipoUsuario} onChange={(e) => setTipoUsuario(e.target.value)} style={{ width: '100%', padding: '10px', backgroundColor: '#27272a', border: 'none', borderRadius: '4px', color: '#fff', marginTop: '4px' }}>
                <option value="ouvinte">Ouvinte / Fã</option>
                <option value="artista">Artista / Banda Independentes</option>
              </select>
            </div>

            <div style={{ marginBottom: '20px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <input type="checkbox" id="lgpd" checked={aceitouLgpd} onChange={(e) => setAceitouLgpd(e.target.checked)} />
              <label htmlFor="lgpd">
                Li e aceito os{' '}
                <span onClick={() => setModalLgpdAberto(true)} style={{ color: '#22c55e', textDecoration: 'underline', cursor: 'pointer' }}>
                  Termos de Uso e Privacidade (LGPD)
                </span>
              </label>
            </div>
          </>
        )}

        <button type="submit" style={{ width: '100%', padding: '12px', backgroundColor: '#22c55e', color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer' }}>
          {isCadastro ? 'Cadastrar' : 'Entrar'}
        </button>

        <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '0.85rem', color: '#a1a1aa' }}>
          {isCadastro ? 'Já possui conta?' : 'Não tem conta?'}{' '}
          <span onClick={() => setIsCadastro(!isCadastro)} style={{ color: '#22c55e', cursor: 'pointer', textDecoration: 'underline' }}>
            {isCadastro ? 'Faça Login' : 'Cadastre-se'}
          </span>
        </p>
      </form>

      <LgpdModal isOpen={modalLgpdAberto} onClose={() => setModalLgpdAberto(false)} />
    </div>
  );
};