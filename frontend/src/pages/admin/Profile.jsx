import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getAdminProfile, updateAdminProfile } from '../../api/adminApi';

export default function AdminProfile(){
  const [profile, setProfile] = useState(null);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');

  const load = async ()=>{
    try { const data = await getAdminProfile(); setProfile(data); setName(data.name); setEmail(data.email); }
    catch(e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };
  useEffect(()=>{ load(); },[]);

  const save = async (e)=>{
    e.preventDefault(); setErr(''); setMsg('');
    try { await updateAdminProfile({ name, email }); setMsg('Profile updated'); load(); }
    catch(e){ setErr(e.response?.data?.error || 'Failed to update'); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Admin Profile</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        {msg && <div className="text-green-600 mb-2">{msg}</div>}
        {profile && (
          <form onSubmit={save} className="bg-white p-4 rounded shadow max-w-lg">
            <input value={name} onChange={e=>setName(e.target.value)} className="border p-2 w-full mb-3" />
            <input value={email} onChange={e=>setEmail(e.target.value)} className="border p-2 w-full mb-3" />
            <button className="bg-indigo-600 text-white px-4 py-2 rounded">Save</button>
          </form>
        )}
      </div>
    </div>
  );
}
