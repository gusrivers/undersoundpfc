import axios from 'axios';

export const api = axios.create({
  baseURL: 'http://localhost:8000/api',
});

// Interceptor para injetar o Token JWT em rotas protegidas
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('undersound_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});