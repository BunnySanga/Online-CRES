import { createContext, useState, useContext, useEffect, useRef } from 'react';

const AuthContext = createContext();

function decodeJwt(token) {
  try {
    const payload = token.split('.')[1];
    const decoded = JSON.parse(atob(payload));
    return decoded;
  } catch (e) {
    return null;
  }
}

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(() => {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    const info = token ? { token, role } : null;
    return info;
  });

  const logoutTimer = useRef();

  const clearLogoutTimer = () => {
    if (logoutTimer.current) {
      clearTimeout(logoutTimer.current);
      logoutTimer.current = null;
    }
  };

  const scheduleAutoLogout = (token) => {
    clearLogoutTimer();
    const payload = decodeJwt(token);
    if (!payload || !payload.exp) return;
    const expiresAt = payload.exp * 1000; // exp is in seconds
    const now = Date.now();
    const delay = Math.max(0, expiresAt - now - 1000); // logout 1s before expiry
    if (delay <= 0) {
      // already expired
      doLogout();
      return;
    }
    logoutTimer.current = setTimeout(() => {
      doLogout();
    }, delay);
  };

  const doLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    setUser(null);
    // force navigate to landing/login
    try {
      window.location.href = '/';
    } catch (e) {
      // ignore
    }
  };

  const login = (token, role) => {
    localStorage.setItem('token', token);
    localStorage.setItem('role', role);
    setUser({ token, role });
    scheduleAutoLogout(token);
  };

  const logout = () => {
    clearLogoutTimer();
    doLogout();
  };

  useEffect(() => {
    // on mount, if token present schedule auto logout
    const token = localStorage.getItem('token');
    if (token) scheduleAutoLogout(token);
    return () => clearLogoutTimer();
  }, []);

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
