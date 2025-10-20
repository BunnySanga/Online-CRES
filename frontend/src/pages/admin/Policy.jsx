import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import axios from '../../api/axiosInstance';

export default function AdminPolicy(){
  const [policies, setPolicies] = useState([]);
  const [text, setText] = useState('');
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');

  const load = async ()=>{
    try{
      const { data } = await axios.get('/policy/all');
      setPolicies(data);
    }catch(e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };
  useEffect(()=>{ load(); },[]);

  const create = async (e)=>{
    e.preventDefault(); setErr(''); setMsg('');
    try{
      await axios.post('/policy', { policy_text: text });
      setMsg('Policy created'); setText(''); load();
    }catch(e){ setErr(e.response?.data?.error || 'Failed to create'); }
  };

  const remove = async (id)=>{
    if (!confirm('Delete this policy?')) return;
    try{
      await axios.delete(`/policy/${id}`); load();
    }catch(e){ setErr(e.response?.data?.error || 'Failed to delete'); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Policies</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        {msg && <div className="text-green-600 mb-2">{msg}</div>}
        <form onSubmit={create} className="bg-white p-4 rounded shadow max-w-3xl mb-6">
          <label className="block text-sm text-gray-600 mb-2">Policy Text</label>
          <textarea value={text} onChange={e=>setText(e.target.value)} className="border p-2 w-full h-40" required />
          <div className="mt-3">
            <button className="bg-indigo-600 text-white px-4 py-2 rounded">Create New Version</button>
          </div>
        </form>

        <div className="bg-white p-4 rounded shadow overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left border-b">
                <th className="p-2">ID</th>
                <th className="p-2">Version</th>
                <th className="p-2">Excerpt</th>
                <th className="p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {policies.map(p => (
                <tr key={p.policy_id} className="border-b">
                  <td className="p-2">{p.policy_id}</td>
                  <td className="p-2">{p.version}</td>
                  <td className="p-2 max-w-xl truncate">{(p.policy_text || '').slice(0, 120)}{(p.policy_text || '').length > 120 ? '…' : ''}</td>
                  <td className="p-2">
                    <button onClick={()=>remove(p.policy_id)} className="text-red-600">Delete</button>
                  </td>
                </tr>
              ))}
              {!policies.length && (
                <tr><td className="p-2 text-gray-500" colSpan="4">No policies yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
