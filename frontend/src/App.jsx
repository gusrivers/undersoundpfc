import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';

const API_URL = 'http://127.0.0.1:8000';

const App = () => {

    const [user, setUser] = useState(null);
    const [token, setToken] = useState(localStorage.getItem('access_token'));
    const [loading, setLoading] = useState(true);
    const [currentPage, setCurrentPage] = useState('login');

    const fetchUser = useCallback(async (authToken) => {
        if (!authToken) {
            setUser(null);
            setLoading(false);
            return;
        }

        try {
            const response = await axios.get(`${API_URL}/users/me`, {
                headers: {
                    Authorization: `Bearer ${authToken}`,
                },
            });
            setUser(response.data);
            setCurrentPage('dashboard');
        } catch (error) {
            console.error('Falha ao validar token:', error);
            localStorage.removeItem('access_token');
            setToken(null);
            setUser(null);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        fetchUser(token);
    }, [token, fetchUser]);
    const handleLogout = () => {
        localStorage.removeItem('access_token');
        setToken(null);
        setUser(null);
        setCurrentPage('login');
    };
    const handleAuthSuccess = (newToken) => {
        localStorage.setItem('access_token', newToken);
        setToken(newToken);
    };
    const AuthContainer = ({ children }) => (
        <div className="min-h-screen bg-gray-950 text-white flex items-center justify-center p-4 font-sans">
            <div className="w-full max-w-lg bg-gray-900 p-8 rounded-xl shadow-2xl space-y-8 border-t-4 border-red-600">
                <h1 className="text-4xl font-extrabold text-red-500 text-center border-b border-gray-700 pb-3">
                    Undersound App
                </h1>
                {children}
            </div>
        </div>
    );

    const Navigation = () => (
        <nav className="flex justify-center space-x-4 mb-8">
            <button
                onClick={() => setCurrentPage('login')}
                className={`px-4 py-2 rounded-full font-semibold transition duration-300 ${
                    currentPage === 'login' ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-700 hover:bg-gray-600'
                }`}
            >
                Login
            </button>
            <button
                onClick={() => setCurrentPage('register')}
                className={`px-4 py-2 rounded-full font-semibold transition duration-300 ${
                    currentPage === 'register' ? 'bg-red-600 hover:bg-red-700' : 'bg-gray-700 hover:bg-gray-600'
                }`}
            >
                Registro
            </button>
        </nav>
    );

    const Dashboard = () => {
        const [isDeleting, setIsDeleting] = useState(false);
        const [deleteMessage, setDeleteMessage] = useState('');

        const handleDelete = async () => {
            console.warn('ATENÇÃO LGPD: Confirmação de exclusão lógica solicitada.');
            
            if (!window.confirm('ATENÇÃO LGPD: Você tem certeza que deseja iniciar o processo de exclusão lógica da sua conta? Seus dados serão desativados, mas mantidos para rastreabilidade. Você será desconectado.')) {
                 return;
            }
            
            setIsDeleting(true);
            try {
                await axios.delete(`${API_URL}/users/me/delete`, {
                    headers: {
                        Authorization: `Bearer ${token}`,
                    },
                });
                setDeleteMessage('Sua conta foi desativada com sucesso (Soft Delete - LGPD). Você será desconectado.');
                setTimeout(handleLogout, 3000);
            } catch (error) {
                setDeleteMessage(`Erro ao desativar conta: ${error.response?.data?.detail || 'Erro de API'}`);
            } finally {
                setIsDeleting(false);
            }
        };

        if (!user) return null;

        return (
            <div className="space-y-6">
                <h2 className="text-3xl font-bold text-center text-red-500">Dashboard (Área Protegida)</h2>
                <div className="bg-gray-800 p-6 rounded-lg space-y-3 border-l-4 border-red-600">
                    <p className="text-lg">
                        <span className="font-semibold text-red-300">Bem-vindo(a),</span> {user.full_name || user.username}!
                    </p>
                    <p className="text-sm text-gray-400">ID: {user.id}</p>
                    <p className="text-sm text-gray-400">Email: {user.email}</p>
                    <p className="text-sm text-gray-400">Conta ativa: {user.is_active ? 'Sim' : 'Não'}</p>
                </div>
                
                <button
                    onClick={handleLogout}
                    className="w-full py-3 bg-gray-700 hover:bg-gray-600 rounded-lg font-semibold transition duration-200"
                >
                    Sair (Logout)
                </button>

                <div className="border-t border-gray-700 pt-4 space-y-4">
                    <h3 className="text-xl font-semibold text-red-500">Controle LGPD (Exclusão)</h3>
                    <p className="text-sm text-gray-400">
                        Ao clicar em "Excluir Conta", o sistema realizará o Soft Delete, desativando o acesso
                        e mantendo o registro apenas para fins de rastreabilidade, conforme a Lei Geral de Proteção de Dados.
                    </p>
                    <button
                        onClick={handleDelete}
                        disabled={isDeleting}
                        className="w-full py-3 bg-red-800 hover:bg-red-700 rounded-lg font-bold transition duration-200 disabled:opacity-50"
                    >
                        {isDeleting ? 'Processando Exclusão...' : 'Excluir Conta (Soft Delete)'}
                    </button>
                    {deleteMessage && <p className={`text-center text-sm ${deleteMessage.includes('Erro') ? 'text-red-500' : 'text-yellow-400'}`}>{deleteMessage}</p>}
                </div>
            </div>
        );
    };

    const LoginForm = () => {
        const [username, setUsername] = useState('');
        const [password, setPassword] = useState('');
        const [error, setError] = useState('');
        const [isSubmitting, setIsSubmitting] = useState(false);

        const handleSubmit = async (e) => {
            e.preventDefault();
            setError('');
            setIsSubmitting(true);
            const formData = new URLSearchParams();
            formData.append('username', username);
            formData.append('password', password);

            try {
                const response = await axios.post(`${API_URL}/token`, formData, {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                });
                handleAuthSuccess(response.data.access_token);
            } catch (err) {
                const detail = err.response?.data?.detail || 'Erro de rede ou servidor indisponível.';
                setError(`Falha no Login: ${detail}`);
                console.error(err);
            } finally {
                setIsSubmitting(false);
            }
        };

        return (
            <form onSubmit={handleSubmit} className="space-y-4">
                <h2 className="text-2xl font-semibold text-center text-red-500">Entrar</h2>
                <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Nome de Usuário"
                    required
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Senha"
                    required
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full py-3 bg-red-600 hover:bg-red-700 rounded-lg font-bold transition duration-200 disabled:opacity-50"
                >
                    {isSubmitting ? 'Verificando...' : 'Login'}
                </button>
                {error && <p className="text-red-500 text-sm text-center">{error}</p>}
            </form>
        );
    };

    const RegisterForm = () => {
        const [formData, setFormData] = useState({
            username: '',
            email: '',
            password: '',
            full_name: '',
        });
        const [message, setMessage] = useState('');
        const [isSuccess, setIsSuccess] = useState(false);
        const [isSubmitting, setIsSubmitting] = useState(false);

        const handleChange = (e) => {
            setFormData({ ...formData, [e.target.name]: e.target.value });
        };

        const handleSubmit = async (e) => {
            e.preventDefault();
            setMessage('');
            setIsSuccess(false);
            setIsSubmitting(true);

            try {
                await axios.post(`${API_URL}/register`, formData);
                setMessage('Usuário registrado com sucesso! Faça o login.');
                setIsSuccess(true);
                setFormData({ username: '', email: '', password: '', full_name: '' });
                setCurrentPage('login');
            } catch (err) {
                const detail = err.response?.data?.detail || 'Erro ao registrar usuário.';
                setMessage(`Falha no Registro: ${detail}`);
                setIsSuccess(false);
                console.error(err);
            } finally {
                setIsSubmitting(false);
            }
        };

        return (
            <form onSubmit={handleSubmit} className="space-y-4">
                <h2 className="text-2xl font-semibold text-center text-red-500">Criar Nova Conta</h2>
                <input
                    type="text"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                    placeholder="Nome de Usuário (Obrigatório)"
                    required
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Email (Obrigatório)"
                    required
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <input
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="Senha (Obrigatório)"
                    required
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <input
                    type="text"
                    name="full_name"
                    value={formData.full_name}
                    onChange={handleChange}
                    placeholder="Nome Completo (Opcional)"
                    className="w-full p-3 bg-gray-800 border border-gray-700 rounded-lg focus:ring-red-500 focus:border-red-500"
                />
                <button
                    type="submit"
                    disabled={isSubmitting}
                    className="w-full py-3 bg-red-600 hover:bg-red-700 rounded-lg font-bold transition duration-200 disabled:opacity-50"
                >
                    {isSubmitting ? 'Registrando...' : 'Criar Conta'}
                </button>
                {message && (
                    <p className={`text-sm text-center ${isSuccess ? 'text-green-500' : 'text-red-500'}`}>
                        {message}
                    </p>
                )}
            </form>
        );
    };

    if (loading) {
        return (
            <AuthContainer>
                <div className="text-center text-xl text-red-500">Carregando Sessão...</div>
            </AuthContainer>
        );
    }

    if (user) {
        return (
            <AuthContainer>
                <Dashboard />
            </AuthContainer>
        );
    }
    return (
        <AuthContainer>
            <Navigation />
            {currentPage === 'login' ? <LoginForm /> : <RegisterForm />}
        </AuthContainer>
    );
};

export default App;
