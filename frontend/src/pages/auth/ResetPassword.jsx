import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import Navbar from '../../components/Navbar';
import { requestPasswordReset, resetPassword } from '../../api/studentsApi';
import { requestAdminPasswordReset, adminResetPassword } from '../../api/adminApi';

export default function ResetPassword(){
  const navigate = useNavigate();
  const { pathname } = useLocation();
  const isAdmin = pathname.startsWith('/admin');

  const [userId, setUserId] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState(1);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);

  const requestOtp = async (e) => {
    e.preventDefault(); setErr(''); setMsg('');
    try {
      setLoading(true);
      const res = isAdmin
        ? await requestAdminPasswordReset(userId)
        : await requestPasswordReset(userId);
      setMsg(res?.message || 'OTP sent to registered email');
      setStep(2);
    } catch (error) {
      setErr(error.response?.data?.error || 'Failed to request reset');
    } finally { setLoading(false); }
  };

  const doReset = async (e) => {
    e.preventDefault(); setErr(''); setMsg('');
    try {
      setLoading(true);
      const res = isAdmin
        ? await adminResetPassword(userId, otp, newPassword)
        : await resetPassword(userId, otp, newPassword);
      setMsg(res?.message || 'Password reset successful');
      setTimeout(() => { navigate('/'); }, 1500);
    } catch (error) {
      setErr(error.response?.data?.error || 'Failed to reset');
    } finally { setLoading(false); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-20 flex justify-center">
        <div className="bg-white p-6 rounded shadow w-96">
          <h2 className="text-xl font-semibold mb-4 text-indigo-700">
            {isAdmin ? 'Admin Reset Password' : 'Reset Password'}
          </h2>
          {msg && <div className="text-green-600 mb-2">{msg}</div>}
          {err && <div className="text-red-600 mb-2">{err}</div>}

          {step === 1 && (
            <form onSubmit={requestOtp}>
              <label className="block text-sm mb-2">
                {isAdmin ? 'Admin ID' : 'User ID'} <span className="text-red-600">*</span>
                <input value={userId} onChange={e=>setUserId(e.target.value)} placeholder={isAdmin ? 'Admin ID' : 'User ID'} className="border p-2 w-full mb-3" required />
              </label>
              <button disabled={loading || !userId} className="bg-indigo-600 text-white w-full py-2 rounded">{loading? 'Sending...' : 'Send OTP'}</button>
            </form>
          )}

          {step === 2 && (
            <form onSubmit={doReset}>
              <label className="block text-sm mb-2">OTP <span className="text-red-600">*</span>
                <input value={otp} onChange={e=>setOtp(e.target.value)} placeholder="OTP" className="border p-2 w-full mb-3" required />
              </label>
              <label className="block text-sm mb-2">New Password <span className="text-red-600">*</span>
                <input type="password" value={newPassword} onChange={e=>setNewPassword(e.target.value)} placeholder="New Password" className="border p-2 w-full mb-3" required />
              </label>
              <button disabled={loading || !otp || !newPassword} className="bg-indigo-600 text-white w-full py-2 rounded">{loading? 'Resetting...' : 'Reset Password'}</button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
