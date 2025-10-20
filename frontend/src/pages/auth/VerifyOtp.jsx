import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { verifyOtp } from '../../api/authApi';
import { useAuth } from '../../context/AuthContext';
import Navbar from '../../components/Navbar';

export default function VerifyOtp(){
  const [otp, setOtp] = useState('');
  const [err, setErr] = useState('');
  const [loading, setLoading] = useState(false);
  const [studentIdInput, setStudentIdInput] = useState('');
  const navigate = useNavigate();
  const { state } = useLocation();
  const studentId = state?.studentId || studentIdInput;
  const { login } = useAuth();

  const submit = async (e) => {
    e.preventDefault();
    setErr('');
    try {
      console.log('Verifying OTP for', studentId);
      setLoading(true);
      const res = await verifyOtp(studentId, otp);
      // backend returns token and maybe role/user
      if (res.token) {
        login(res.token, res.role || 'STUDENT');
        navigate('/student/dashboard');
      } else {
        setErr('No token received');
      }
    } catch (error) {
      setErr(error.response?.data?.error || 'Verification failed');
      console.error('verifyOtp error', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-20 flex justify-center">
        <form onSubmit={submit} className="bg-white p-6 rounded shadow w-80">
          <h2 className="text-xl font-semibold mb-4 text-indigo-700">Verify OTP</h2>
          <p className="text-sm mb-3">OTP was sent to the email linked to student ID <strong>{studentId || '...'}</strong></p>
          {!state?.studentId && (
            <input value={studentIdInput} onChange={e=>setStudentIdInput(e.target.value)} placeholder="Student ID (if not auto-filled)" className="border p-2 w-full mb-3" />
          )}
          {err && <p className="text-red-600 mb-2">{err}</p>}
          <input value={otp} onChange={e=>setOtp(e.target.value)} placeholder="Enter OTP" className="border p-2 w-full mb-4" />
          <button disabled={loading} className="bg-indigo-600 text-white w-full py-2 rounded disabled:opacity-60">{loading ? 'Verifying...' : 'Verify'}</button>
        </form>
      </div>
    </div>
  );
}
