import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { studentLogin } from '../../api/authApi';
import Navbar from '../../components/Navbar';
import { useAuth } from '../../context/AuthContext';

export default function StudentLogin() {
  const [studentId, setStudentId] = useState('');
  const [password, setPassword] = useState('');
  const [step] = useState('login'); // keep for compatibility
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

  React.useEffect(() => {
    const token = localStorage.getItem('token');
    const role = localStorage.getItem('role');
    if (token) {
      if (role === 'STUDENT') {
        navigate('/student/dashboard');
        return;
      }
      // if another role is logged in (e.g., ADMIN), clear it so student can log in here
      if (role !== 'STUDENT') {
        try { logout(); } catch (e) { /* ignore */ }
      }
    }
  }, []);

  const submitLogin = async (e) => {
    e.preventDefault();
    setErr('');
    try {
      console.log('Submitting login for', studentId);
      setLoading(true);
      await studentLogin(studentId, password);
      // OTP sent -> go to verify page
      navigate('/student/verify-otp', { state: { studentId } });
    } catch (error) {
      // show server-provided error (invalid credentials) instead of redirecting
      setErr(error.response?.data?.error || 'Login failed');
      console.error('studentLogin error', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-20 flex justify-center">
        <div className="max-w-md w-full bg-white p-6 rounded shadow">
          <h2 className="text-xl font-semibold mb-4 text-indigo-700">Student Sign In</h2>

          {err && <div className="text-red-600 mb-3">{err}</div>}

          {step === 'login' ? (
            <form onSubmit={submitLogin}>
              <label className="block mb-2 text-sm">Student ID <span className="text-red-600">*</span>
                <input value={studentId} onChange={e=>setStudentId(e.target.value)} placeholder="Student ID" aria-label="Student ID" required className="w-full border p-2 mb-3 rounded" />
              </label>
              <label className="block mb-4 text-sm">Password <span className="text-red-600">*</span>
                <input value={password} onChange={e=>setPassword(e.target.value)} placeholder="Password" type="password" aria-label="Password" required className="w-full border p-2 mb-3 rounded" />
              </label>
              <button type="submit" disabled={loading || !studentId || !password} className="w-full bg-indigo-600 text-white py-2 rounded disabled:opacity-60">
                {loading ? 'Sending...' : 'Send OTP'}
              </button>
              <div className="mt-3 text-right">
                <a href="/student/reset-password" className="text-sm text-indigo-600">Forgot password?</a>
              </div>
            </form>
          ) : null}
        </div>
      </div>
    </div>
  );
}
