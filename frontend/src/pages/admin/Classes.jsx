import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { listClasses, createClass, deleteClass } from '../../api/adminApi';

export default function AdminClasses(){
  const [classes, setClasses] = useState([]);
  const [name, setName] = useState('');
  const [err, setErr] = useState('');
  const [msg, setMsg] = useState('');

  const load = async ()=>{
    try { setErr(''); const data = await listClasses(); setClasses(data); }
    catch (e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };
  useEffect(()=>{ load(); },[]);

  const submit = async (e)=>{
    e.preventDefault(); setErr(''); setMsg('');
    try { await createClass(name); setMsg('Class created'); setName(''); load(); }
    catch(e){ setErr(e.response?.data?.error || 'Failed to create'); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Classes</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        {msg && <div className="text-green-600 mb-2">{msg}</div>}

        <form onSubmit={submit} className="bg-white p-4 rounded shadow max-w-lg mb-6 flex gap-2 items-end">
          <label className="flex-1 text-sm">Class name <span className="text-red-600">*</span>
            <input value={name} onChange={e=>setName(e.target.value)} placeholder="Class name" className="border p-2 w-full mt-1" required />
          </label>
          <button disabled={!name} className="bg-indigo-600 text-white px-4 py-2 rounded disabled:opacity-60">Add</button>
        </form>

        <div className="bg-white rounded shadow">
          {classes.map(c => (
            <div key={c.class_id} className="p-3 border-b flex items-center justify-between">
              <div>{c.class_name}</div>
              <button onClick={async()=>{ await deleteClass(c.class_id); load(); }} className="text-red-600">Delete</button>
            </div>
          ))}
          {!classes.length && <div className="p-4 text-gray-600">No classes</div>}
        </div>
      </div>
    </div>
  );
}
