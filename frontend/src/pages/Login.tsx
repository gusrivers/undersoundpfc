import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { LgpdModal } from '../components/LgpdModal';
import { CheckCircle2, Eye, EyeOff, X } from 'lucide-react';

export const Login: React.FC = () => {
  const [isCadastro, setIsCadastro] = useState(false);
  const [nome, setNome] = useState('');
  const [email, setEmail] = useState('');
  const [senha, setSenha] = useState('');
  const [mostrarSenha, setMostrarSenha] = useState(false);
  const [tipoUsuario, setTipoUsuario] = useState('ouvinte');
  const [aceitouLgpd, setAceitouLgpd] = useState(false);
  const [modalLgpdAberto, setModalLgpdAberto] = useState(false);
  const [erro, setErro] = useState('');
  const [mensagemSucesso, setMensagemSucesso] = useState('');

  // Estados do modal "Esqueci minha senha"
  const [modalRecuperacaoAberto, setModalRecuperacaoAberto] = useState(false);
  const [etapaRecuperacao, setEtapaRecuperacao] = useState<'solicitar' | 'redefinir'>('solicitar');
  const [emailRecuperacao, setEmailRecuperacao] = useState('');
  const [tokenRecuperacao, setTokenRecuperacao] = useState('');
  const [novaSenha, setNovaSenha] = useState('');
  const [mostrarNovaSenha, setMostrarNovaSenha] = useState(false);
  const [carregandoRecuperacao, setCarregandoRecuperacao] = useState(false);
  const [erroRecuperacao, setErroRecuperacao] = useState('');
  const [infoRecuperacao, setInfoRecuperacao] = useState('');

  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErro('');
    setMensagemSucesso('');

    try {
      if (isCadastro) {
        if (!aceitouLgpd) {
          setErro('Você precisa aceitar os Termos de Uso (LGPD) para prosseguir.');
          return;
        }
        await api.post('/auth/cadastro', {
          nome, email, senha, tipo_usuario: tipoUsuario, aceitou_termos_lgpd: aceitouLgpd
        });
        setSenha('');
        setMostrarSenha(false);
        setIsCadastro(false);
        setMensagemSucesso('Cadastro realizado com sucesso! Insira sua senha para entrar.');
      } else {
        const response = await api.post('/auth/login', { email, senha });
        localStorage.setItem('undersound_token', response.data.access_token);
        navigate('/');
      }
    } catch (err: any) {
      setErro(err.response?.data?.detail || 'Erro na operação. Verifique seus dados.');
    }
  };

  const abrirModalRecuperacao = () => {
    setEmailRecuperacao(email);
    setTokenRecuperacao('');
    setNovaSenha('');
    setMostrarNovaSenha(false);
    setErroRecuperacao('');
    setInfoRecuperacao('');
    setEtapaRecuperacao('solicitar');
    setModalRecuperacaoAberto(true);
  };

  const fecharModalRecuperacao = () => {
    setMostrarNovaSenha(false);
    setModalRecuperacaoAberto(false);
  };

  const handleSolicitarToken = async (e: React.FormEvent) => {
    e.preventDefault();
    setCarregandoRecuperacao(true);
    setErroRecuperacao('');
    setInfoRecuperacao('');

    try {
      const res = await api.post('/auth/esqueci-senha', { email: emailRecuperacao });
      setInfoRecuperacao(
        res.data.token_teste
          ? `${res.data.mensagem} Token de teste: ${res.data.token_teste}`
          : res.data.mensagem
      );
      if (res.data.token_teste) {
        setTokenRecuperacao(res.data.token_teste);
      }
      setEtapaRecuperacao('redefinir');
    } catch (err: any) {
      setErroRecuperacao(err.response?.data?.detail || 'Não foi possível solicitar a recuperação.');
    } finally {
      setCarregandoRecuperacao(false);
    }
  };

  const handleRedefinirSenha = async (e: React.FormEvent) => {
    e.preventDefault();
    setCarregandoRecuperacao(true);
    setErroRecuperacao('');
    setInfoRecuperacao('');

    try {
      const res = await api.post('/auth/redefinir-senha', {
        token: tokenRecuperacao.trim(),
        nova_senha: novaSenha,
      });
      setMostrarNovaSenha(false);
      setModalRecuperacaoAberto(false);
      setSenha('');
      setMostrarSenha(false);
      setMensagemSucesso(res.data.mensagem || 'Senha atualizada com sucesso!');
    } catch (err: any) {
      setErroRecuperacao(err.response?.data?.detail || 'Não foi possível redefinir a senha.');
    } finally {
      setCarregandoRecuperacao(false);
    }
  };

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center',
      minHeight: 'calc(100vh - 60px)', backgroundColor: '#09090b', color: '#fff', padding: '20px'
    }}>

      {/* LOGO DA MARCA */}
      <div style={{ textAlign: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px', marginBottom: '8px' }}>
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

      <form
        onSubmit={handleSubmit}
        style={{
          backgroundColor: '#18181b',
          padding: '32px',
          borderRadius: '12px',
          border: '1px solid #27272a',
          width: '100%',
          maxWidth: '400px',
          boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5)',
          boxSizing: 'border-box',
          textAlign: 'left'
        }}
      >
        <h2 style={{ margin: '0 0 20px 0', textAlign: 'center', fontSize: '1.2rem', color: '#e4e4e7' }}>
          {isCadastro ? 'Criar Nova Conta' : 'Acessar Undersound'}
        </h2>

        {mensagemSucesso && (
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
            <span>{mensagemSucesso}</span>
          </div>
        )}

        {erro && (
          <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px 12px', borderRadius: '6px', marginBottom: '16px', fontSize: '0.85rem', border: '1px solid #7f1d1d' }}>
            {erro}
          </div>
        )}

        {isCadastro && (
          <div style={{ marginBottom: '16px', textAlign: 'left' }}>
            <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
              Nome Completo / Banda
            </label>
            <input
              type="text"
              value={nome}
              onChange={(e) => setNome(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '10px',
                backgroundColor: '#27272a',
                border: '1px solid #3f3f46',
                borderRadius: '6px',
                color: '#fff',
                marginTop: '4px',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
          </div>
        )}

        <div style={{ marginBottom: '16px', textAlign: 'left' }}>
          <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
            E-mail
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{
              width: '100%',
              padding: '10px',
              backgroundColor: '#27272a',
              border: '1px solid #3f3f46',
              borderRadius: '6px',
              color: '#fff',
              marginTop: '4px',
              outline: 'none',
              boxSizing: 'border-box'
            }}
          />
        </div>

        <div style={{ marginBottom: isCadastro ? '16px' : '10px', textAlign: 'left' }}>
          <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
            Senha
          </label>
          <div style={{ position: 'relative', marginTop: '4px' }}>
            <input
              type={mostrarSenha ? 'text' : 'password'}
              value={senha}
              onChange={(e) => setSenha(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '10px 40px 10px 10px',
                backgroundColor: '#27272a',
                border: '1px solid #3f3f46',
                borderRadius: '6px',
                color: '#fff',
                outline: 'none',
                boxSizing: 'border-box'
              }}
            />
            <button
              type="button"
              onClick={() => setMostrarSenha((prev) => !prev)}
              aria-label={mostrarSenha ? 'Ocultar senha' : 'Mostrar senha'}
              title={mostrarSenha ? 'Ocultar senha' : 'Mostrar senha'}
              style={{
                position: 'absolute',
                right: '10px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'transparent',
                border: 'none',
                color: '#a1a1aa',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                padding: '2px'
              }}
            >
              {mostrarSenha ? <EyeOff size={18} /> : <Eye size={18} />}
            </button>
          </div>
        </div>

        {!isCadastro && (
          <div style={{ marginBottom: '18px', textAlign: 'right' }}>
            <span
              onClick={abrirModalRecuperacao}
              style={{ fontSize: '0.82rem', color: '#ef4444', cursor: 'pointer', textDecoration: 'underline' }}
            >
              Esqueci minha senha
            </span>
          </div>
        )}

        {isCadastro && (
          <>
            <div style={{ marginBottom: '16px', textAlign: 'left' }}>
              <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
                Tipo de Perfil
              </label>
              <select
                value={tipoUsuario}
                onChange={(e) => setTipoUsuario(e.target.value)}
                style={{
                  width: '100%',
                  padding: '10px',
                  backgroundColor: '#27272a',
                  border: '1px solid #3f3f46',
                  borderRadius: '6px',
                  color: '#fff',
                  marginTop: '4px',
                  outline: 'none',
                  boxSizing: 'border-box'
                }}
              >
                <option value="ouvinte">Ouvinte / Fã</option>
                <option value="artista">Artista / Banda Independentes</option>
              </select>
            </div>

            <div style={{ marginBottom: '20px', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '8px', textAlign: 'left' }}>
              <input
                type="checkbox"
                id="lgpd"
                checked={aceitouLgpd}
                onChange={(e) => setAceitouLgpd(e.target.checked)}
                style={{ accentColor: '#ef4444', cursor: 'pointer', width: '16px', height: '16px', flexShrink: 0 }}
              />
              <label htmlFor="lgpd" style={{ cursor: 'pointer', color: '#d4d4d8', textAlign: 'left' }}>
                Li e aceito os{' '}
                <span
                  onClick={(e) => { e.preventDefault(); setModalLgpdAberto(true); }}
                  style={{ color: '#ef4444', textDecoration: 'underline', cursor: 'pointer', fontWeight: 'bold' }}
                >
                  Termos de Uso e Privacidade (LGPD)
                </span>
              </label>
            </div>
          </>
        )}

        <button
          type="submit"
          style={{
            width: '100%',
            padding: '12px',
            backgroundColor: '#ef4444',
            color: '#fff',
            fontWeight: 'bold',
            border: 'none',
            borderRadius: '6px',
            cursor: 'pointer',
            fontSize: '0.95rem',
            boxSizing: 'border-box'
          }}
        >
          {isCadastro ? 'Cadastrar Conta' : 'Entrar'}
        </button>

        <p style={{ textAlign: 'center', marginTop: '16px', fontSize: '0.85rem', color: '#a1a1aa' }}>
          {isCadastro ? 'Já possui conta?' : 'Não tem conta?'}{' '}
          <span
            onClick={() => { setIsCadastro(!isCadastro); setMostrarSenha(false); setErro(''); setMensagemSucesso(''); }}
            style={{ color: '#ef4444', cursor: 'pointer', textDecoration: 'underline', fontWeight: 'bold' }}
          >
            {isCadastro ? 'Faça Login' : 'Cadastre-se'}
          </span>
        </p>
      </form>

      {modalRecuperacaoAberto && (
        <div style={{ position: 'fixed', top: 0, left: 0, width: '100vw', height: '100vh', backgroundColor: 'rgba(0,0,0,0.85)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 1100, padding: '16px' }}>
          <div style={{ backgroundColor: '#18181b', padding: '28px', borderRadius: '8px', border: '1px solid #27272a', width: '100%', maxWidth: '420px', boxSizing: 'border-box', textAlign: 'left' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ margin: 0, fontSize: '1.15rem' }}>Recuperar Senha</h3>
              <button
                type="button"
                onClick={fecharModalRecuperacao}
                style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer', padding: '4px' }}
                title="Fechar"
              >
                <X size={20} />
              </button>
            </div>

            {erroRecuperacao && (
              <div style={{ backgroundColor: '#450a0a', color: '#fca5a5', padding: '10px', borderRadius: '4px', marginBottom: '14px', fontSize: '0.82rem', border: '1px solid #7f1d1d' }}>
                {erroRecuperacao}
              </div>
            )}

            {infoRecuperacao && (
              <div style={{ backgroundColor: '#27272a', color: '#e4e4e7', padding: '10px', borderRadius: '4px', marginBottom: '14px', fontSize: '0.8rem', border: '1px solid #3f3f46', wordBreak: 'break-all' }}>
                {infoRecuperacao}
              </div>
            )}

            {etapaRecuperacao === 'solicitar' ? (
              <form onSubmit={handleSolicitarToken}>
                <p style={{ fontSize: '0.82rem', color: '#a1a1aa', marginTop: 0, marginBottom: '14px' }}>
                  Informe o e-mail da sua conta para gerar o token de redefinição de senha.
                </p>
                <div style={{ marginBottom: '18px', textAlign: 'left' }}>
                  <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
                    E-mail cadastrado
                  </label>
                  <input
                    type="email"
                    value={emailRecuperacao}
                    onChange={(e) => setEmailRecuperacao(e.target.value)}
                    required
                    style={{
                      width: '100%',
                      padding: '10px',
                      backgroundColor: '#27272a',
                      border: '1px solid #3f3f46',
                      borderRadius: '4px',
                      color: '#fff',
                      marginTop: '4px',
                      outline: 'none',
                      boxSizing: 'border-box'
                    }}
                  />
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={fecharModalRecuperacao}
                    style={{ padding: '8px 14px', backgroundColor: '#27272a', color: '#fff', border: '1px solid #3f3f46', borderRadius: '4px', cursor: 'pointer', fontSize: '0.85rem' }}
                  >
                    Cancelar
                  </button>
                  <button
                    type="submit"
                    disabled={carregandoRecuperacao}
                    style={{ padding: '8px 16px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 'bold' }}
                  >
                    {carregandoRecuperacao ? 'Enviando...' : 'Gerar Token'}
                  </button>
                </div>
              </form>
            ) : (
              <form onSubmit={handleRedefinirSenha}>
                <div style={{ marginBottom: '12px', textAlign: 'left' }}>
                  <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
                    Token de Redefinição
                  </label>
                  <input
                    type="text"
                    value={tokenRecuperacao}
                    onChange={(e) => setTokenRecuperacao(e.target.value)}
                    required
                    style={{
                      width: '100%',
                      padding: '10px',
                      backgroundColor: '#27272a',
                      border: '1px solid #3f3f46',
                      borderRadius: '4px',
                      color: '#fff',
                      marginTop: '4px',
                      outline: 'none',
                      boxSizing: 'border-box'
                    }}
                  />
                </div>
                <div style={{ marginBottom: '18px', textAlign: 'left' }}>
                  <label style={{ display: 'block', textAlign: 'left', fontSize: '0.85rem', color: '#a1a1aa' }}>
                    Nova Senha
                  </label>
                  <div style={{ position: 'relative', marginTop: '4px' }}>
                    <input
                      type={mostrarNovaSenha ? 'text' : 'password'}
                      value={novaSenha}
                      onChange={(e) => setNovaSenha(e.target.value)}
                      required
                      style={{
                        width: '100%',
                        padding: '10px 40px 10px 10px',
                        backgroundColor: '#27272a',
                        border: '1px solid #3f3f46',
                        borderRadius: '4px',
                        color: '#fff',
                        outline: 'none',
                        boxSizing: 'border-box'
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setMostrarNovaSenha((prev) => !prev)}
                      aria-label={mostrarNovaSenha ? 'Ocultar nova senha' : 'Mostrar nova senha'}
                      title={mostrarNovaSenha ? 'Ocultar nova senha' : 'Mostrar nova senha'}
                      style={{
                        position: 'absolute',
                        right: '10px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'transparent',
                        border: 'none',
                        color: '#a1a1aa',
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        padding: '2px'
                      }}
                    >
                      {mostrarNovaSenha ? <EyeOff size={18} /> : <Eye size={18} />}
                    </button>
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                  <button
                    type="button"
                    onClick={() => { setMostrarNovaSenha(false); setEtapaRecuperacao('solicitar'); }}
                    style={{ padding: '8px 12px', backgroundColor: '#27272a', color: '#a1a1aa', border: '1px solid #3f3f46', borderRadius: '4px', cursor: 'pointer', fontSize: '0.82rem' }}
                  >
                    Voltar
                  </button>
                  <button
                    type="submit"
                    disabled={carregandoRecuperacao}
                    style={{ padding: '8px 16px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontSize: '0.85rem', fontWeight: 'bold' }}
                  >
                    {carregandoRecuperacao ? 'Salvando...' : 'Redefinir Senha'}
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      <LgpdModal isOpen={modalLgpdAberto} onClose={() => setModalLgpdAberto(false)} />
    </div>
  );
};