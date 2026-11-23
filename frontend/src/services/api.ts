import axios from 'axios';

const RAW_API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const CLEAN_API_URL = RAW_API_URL.replace(/\/+$/, '');
const BASE_URL = CLEAN_API_URL.endsWith('/api')
  ? CLEAN_API_URL
  : `${CLEAN_API_URL}/api`;

export const api = axios.create({
  baseURL: BASE_URL,
});

// Interceptor para injetar o Token JWT em rotas protegidas
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('undersound_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});