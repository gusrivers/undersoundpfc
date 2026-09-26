import React from 'react';
import { X, ShieldCheck } from 'lucide-react';

interface LgpdModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const LgpdModal: React.FC<LgpdModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.8)', display: 'flex',
      alignItems: 'center', justifyContent: 'center', zIndex: 1000
    }}>
      <div style={{
        backgroundColor: '#18181b', color: '#f4f4f5', padding: '24px',
        borderRadius: '8px', maxWidth: '600px', width: '90%', maxHeight: '80vh',
        overflowY: 'auto', border: '1px solid #27272a'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: 0, fontSize: '1.25rem' }}>
            <ShieldCheck color="#22c55e" /> Termos de Uso e Privacidade (LGPD)
          </h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#a1a1aa', cursor: 'pointer' }}>
            <X size={20} />
          </button>
        </div>
        <div style={{ fontSize: '0.9rem', lineHeight: '1.5', color: '#d4d4d8' }}>
          <p><strong>1. Coleta de Dados:</strong> O projeto Undersound coleta estritamente dados necessários para autenticação e gestão do perfil (Nome, E-mail e Tipo de Conta).</p>
          <p><strong>2. Finalidade:</strong> Seus dados serão utilizados exclusivamente para identificação do usuário e gestão de autorização de publicação de acervos musicais na plataforma.</p>
          <p><strong>3. Armazenamento e Direitos:</strong> Os dados são armazenados de forma segura com senhas criptografadas por hashes matemáticos de via única. Você pode solicitar a exclusão da sua conta a qualquer momento.</p>
        </div>
        <button 
          onClick={onClose} 
          style={{
            marginTop: '20px', width: '100%', padding: '10px', backgroundColor: '#22c55e',
            color: '#000', fontWeight: 'bold', border: 'none', borderRadius: '4px', cursor: 'pointer'
          }}
        >
          Entendido e Ciente
        </button>
      </div>
    </div>
  );
};