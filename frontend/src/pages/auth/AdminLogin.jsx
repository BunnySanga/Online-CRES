import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { adminLogin } from '../../api/authApi';
import { useAuth } from '../../context/AuthContext';
import Navbar from '../../components/Navbar';

export default function AdminLogin() {
  const [adminId, setAdminId] = useState('');
  const [password, setPassword] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { login, logout } = useAuth();

  React.useEffect(() => {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    if (token) {
      if (role === 'ADMIN') {
        navigate('/admin/dashboard');
        return;
      }
      if (role !== 'ADMIN') {
        try { logout(); } catch { /* ignore */ }
      }
    }
  }, []);

  const submit = async e => {
    e.preventDefault();
    setErr('');
    try {
      setLoading(true);
      const res = await adminLogin(adminId, password);
      login(res.token, 'ADMIN');
      navigate('/admin/dashboard');
    } catch (error) {
      console.error(error);
      setErr(error.response?.data?.error || (error.message ? error.message : 'Login failed'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-20 flex justify-center">
        <form onSubmit={submit} className="bg-white p-8 rounded shadow w-full max-w-md">
          <h2 className="text-2xl mb-4 text-indigo-700">Administrator Sign In</h2>
          {err && <div role="alert" className="text-red-600 mb-3">{err}</div>}

          <label className="block mb-2 text-sm font-medium">Admin ID <span className="text-red-600">*</span>
            <input
              value={adminId}
              onChange={e=>setAdminId(e.target.value)}
              placeholder="Admin ID"
              aria-label="Admin ID"
              required
              className="w-full border p-2 mb-3 rounded mt-1"
            />
          </label>

          <label className="block mb-2 text-sm font-medium">Password <span className="text-red-600">*</span>
            <input
              value={password}
              onChange={e=>setPassword(e.target.value)}
              placeholder="Password"
              type="password"
              aria-label="Password"
              required
              className="w-full border p-2 rounded mt-1"
            />
          </label>

          {/* Forgot password link */}
          <div className="flex justify-end mb-5">
            <Link to="/admin/reset-password" className="text-sm text-indigo-600 hover:underline">
              Forgot password?
            </Link>
          </div>

          <button disabled={loading || !adminId || !password} className="w-full bg-indigo-600 text-white py-2 rounded disabled:opacity-60">
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}
