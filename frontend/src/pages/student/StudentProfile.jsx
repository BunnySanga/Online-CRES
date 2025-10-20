import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getMyProfile, requestPasswordReset, resetPassword } from '../../api/studentsApi';

export default function StudentProfile(){
  const [profile, setProfile] = useState(null);
  const [otpRequested, setOtpRequested] = useState(false);
  const [otp, setOtp] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [msg, setMsg] = useState('');
  const [errMsg, setErrMsg] = useState('');

  useEffect(()=>{
    const fetch = async ()=>{
      try{
        const res = await getMyProfile();
        setProfile(res);
      }catch(err){
        console.error(err);
      }
    };
    fetch();
  },[]);

  const requestReset = async () => {
    try {
      if (!profile?.student_id) return;
      setErrMsg(''); setMsg('');
      const res = await requestPasswordReset(profile.student_id);
      setMsg(res?.message || 'Reset OTP sent to your Gmail. Please enter it below.');
      setOtpRequested(true);
    } catch (e) {
      setErrMsg(e.response?.data?.error || 'Failed to request');
    }
  };

  const submitReset = async (e) => {
    e.preventDefault(); setErrMsg(''); setMsg('');
    if (!otp || !newPw || !confirmPw) { setErrMsg('Please fill all fields'); return; }
    if (newPw.length < 6) { setErrMsg('Password must be at least 6 characters'); return; }
    if (newPw !== confirmPw) { setErrMsg('Passwords do not match'); return; }
    try {
      const r = await resetPassword(profile.student_id, otp, newPw);
      setMsg(r?.message || 'Password reset successful');
      setOtp(''); setNewPw(''); setConfirmPw(''); setOtpRequested(false);
    } catch (e) {
      setErrMsg(e.response?.data?.error || 'Failed to reset password');
    }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <main className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">My Profile</h1>
        {!profile ? (
          <div className="bg-white p-6 rounded shadow max-w-md">Loading...</div>
        ) : (
          <div className="bg-white p-6 rounded shadow max-w-xl">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <div className="text-sm text-gray-500">Student ID</div>
                <div className="font-medium">{profile.student_id}</div>
              </div>
              <div>
                <div className="text-sm text-gray-500">Name</div>
                <div className="font-medium">{profile.name}</div>
              </div>
              <div>
                <div className="text-sm text-gray-500">Email</div>
                <div className="font-medium">{profile.email}</div>
              </div>
              <div>
                <div className="text-sm text-gray-500">Class</div>
                <div className="font-medium">{profile.class_name}</div>
              </div>
            </div>
            <div className="mt-6">
              <button onClick={requestReset} className="bg-indigo-600 hover:bg-indigo-700 transition text-white px-4 py-2 rounded">Request Password Reset</button>
              {(msg || errMsg) && <div className={`mt-3 text-sm ${errMsg? 'text-red-600':'text-green-600'}`}>{errMsg || msg}</div>}
              {otpRequested && (
                <form onSubmit={submitReset} className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <label className="text-sm">
                    OTP
                    <input value={otp} onChange={e=>setOtp(e.target.value)} placeholder="Enter OTP" className="border p-2 w-full mt-1" required />
                  </label>
                  <div className="sm:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <label className="text-sm">
                      New Password
                      <input type="password" value={newPw} onChange={e=>setNewPw(e.target.value)} placeholder="New password" className="border p-2 w-full mt-1" required />
                    </label>
                    <label className="text-sm">
                      Confirm Password
                      <input type="password" value={confirmPw} onChange={e=>setConfirmPw(e.target.value)} placeholder="Confirm password" className="border p-2 w-full mt-1" required />
                    </label>
                  </div>
                  <div className="sm:col-span-2">
                    <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded">Set New Password</button>
                  </div>
                </form>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}