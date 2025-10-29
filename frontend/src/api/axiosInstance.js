/*
 * Axios Instance
 *
 * Configures a reusable axios instance for API requests, including base URL, credentials,
 * and interceptors for authentication and error handling.
 *
 * Features:
 *   - Attaches JWT token from localStorage to requests
 *   - Handles 401 Unauthorized responses by clearing auth and redirecting to login
 *
 * Usage:
 *   import axiosInstance from './axiosInstance';
 */

import axios from 'axios';

/*
 * Smart API base URL configuration based on environment mode
 * - Development: Uses '/api' with Vite proxy (localhost only)
 * - Production: Uses direct backend URL provided via env
 */
const MODE = import.meta?.env?.MODE || 'development';
const API_BASE_URL =
  MODE === 'development'
    ? (import.meta?.env?.VITE_API_BASE_URL_DEV || '/api')
    : (import.meta?.env?.VITE_API_BASE_URL_PROD || '/api');

const axiosInstance = axios.create({
  /*
   * If API_BASE_URL is undefined in production, requests will use relative URLs.
   * Prefer setting VITE_API_BASE_URL to an absolute URL when frontend and backend are on different domains.
   */
  baseURL: API_BASE_URL,
  withCredentials: true,
});

axiosInstance.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// response interceptor: auto logout on 401 to keep frontend in-sync with backend session
axiosInstance.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err?.response?.status;
    const reqUrl = err?.config?.url || '';
    const token = localStorage.getItem('token');
    // don't auto-redirect when the 401 comes from auth endpoints (login/verify) or when there's no token
    const isAuthEndpoint =
      reqUrl.includes('/auth/login') ||
      reqUrl.includes('/auth/admin/login') ||
      reqUrl.includes('/auth/verify-otp') ||
      reqUrl.includes('/auth/request-reset') ||
      reqUrl.includes('/auth/reset-password') ||
      reqUrl.includes('/auth/change-password');

    if (status === 401 && token && !isAuthEndpoint) {
      console.error('Unauthorized (401) received from API for protected request. Clearing auth.');
      localStorage.removeItem('token');
      localStorage.removeItem('role');
      // redirect to login
      try {
        window.location.href = '/';
      } catch (e) {}
    }
    return Promise.reject(err);
  },
);

export default axiosInstance;
