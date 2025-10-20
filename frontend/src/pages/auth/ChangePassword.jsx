import React, { useState } from 'react';
import Navbar from '../../components/Navbar';
import axios from '../../api/axiosInstance';
import { useNavigate } from 'react-router-dom';

export default function ChangePassword(){
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const submit = async (e) => {
    e.preventDefault(); setErr(''); setMsg('');
    if (newPassword.length < 6) { setErr('Password must be at least 6 characters'); return; }
    if (newPassword !== confirmPassword) { setErr('Passwords do not match'); return; }
    try {
      setLoading(true);
      const res = await axios.post('/auth/change-password', { newPassword });
      setMsg(res?.message || 'Password changed successfully');
      setTimeout(()=> navigate('/student/dashboard'), 800);
    } catch (e) {
      setErr(e.response?.data?.error || 'Failed to change password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-20 flex justify-center">
        <form onSubmit={submit} className="bg-white p-6 rounded shadow w-96">
          <h2 className="text-xl font-semibold mb-4 text-indigo-700">Set Your Password</h2>
          {msg && <div className="text-green-600 mb-2">{msg}</div>}
          {err && <div className="text-red-600 mb-2">{err}</div>}
          <input type="password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} placeholder="New password" className="border p-2 w-full mb-3" required />
          <input type="password" value={confirmPassword} onChange={e=>setConfirmPassword(e.target.value)} placeholder="Confirm password" className="border p-2 w-full mb-4" required />
          <button disabled={loading} className="bg-indigo-600 text-white w-full py-2 rounded disabled:opacity-60">{loading? 'Saving...' : 'Save Password'}</button>
        </form>
      </div>
    </div>
  );
}
