import React, { useState } from 'react';
import { studentLogin } from '../../api/authApi';
import { useNavigate } from 'react-router-dom';
import Input from '../../components/ui/Input';
import Button from '../../components/ui/Button';
import { useToast } from '../../components/ui/ToastProvider';

export default function StudentLogin() {
  const [studentId, setStudentId] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const { push } = useToast();
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await studentLogin(studentId, password);
      push(res.message || 'OTP sent to email', 'success');
      navigate('/verify-otp', { state: { studentId } });
    } catch (err) {
      setError(err.response?.data?.error || 'Login failed');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100">
      <form onSubmit={handleSubmit} className="bg-white p-6 rounded shadow w-80">
        <h2 className="text-xl font-semibold mb-4">Student Login</h2>
        {error && <p className="text-red-600 mb-2">{error}</p>}
        <Input value={studentId} onChange={(e)=>setStudentId(e.target.value)} placeholder="Student ID" required />
        <div className="h-3" />
        <Input value={password} onChange={(e)=>setPassword(e.target.value)} type="password" placeholder="Password" required />
        <div className="h-4" />
        <Button className="w-full" type="submit">Login</Button>
      </form>
    </div>
  );
}
