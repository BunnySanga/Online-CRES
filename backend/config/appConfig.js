// config/appConfig.js
const path = require('path');
// Always load env from backend/.env when running from repo root
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

/*
 * Application Configuration
 * 
 * This module provides configuration values for the application, including environment variables,
 * server port, and allowed origins for CORS validation. It reads values from the environment
 * and provides defaults for development.
 * 
 * Exports:
 * - NODE_ENV: The current environment (e.g., 'development', 'production').
 * - PORT: The port number the server listens on.
 * - FRONTEND_ORIGIN: The origin URL for the frontend application.
 * - allowlist: A Set of allowed origins for CORS validation.
 */

const NODE_ENV = process.env.NODE_ENV || 'development';
const PORT = process.env.PORT || 5500;
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  (NODE_ENV === 'development' ? 'http://localhost:5173' : '');

// Dynamic CORS origins - supports both local development and production
const getOrigins = () => {
  const origins = [];
  
  // Add configured frontend origin
  if (FRONTEND_ORIGIN) {
    origins.push(FRONTEND_ORIGIN);
  }
  
  // Only add localhost origins in development
  if (NODE_ENV === 'development') {
    origins.push(
      'http://localhost:5173',
      'http://127.0.0.1:5173',
      'http://localhost:5174',
      'http://127.0.0.1:5174'
    );
  }
  
  return origins;
};

const allowlist = new Set(getOrigins());

module.exports = {
  NODE_ENV,
  PORT,
  FRONTEND_ORIGIN,
  allowlist,
};
