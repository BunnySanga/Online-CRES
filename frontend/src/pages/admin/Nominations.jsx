import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getElections } from '../../api/electionApi';
import axios from '../../api/axiosInstance';

export default function AdminNominations(){
  const [electionId, setElectionId] = useState('');
  const [noms, setNoms] = useState([]);
  const [err, setErr] = useState('');

  const load = async (id)=>{
    try { const { data } = await axios.get(`/nominations/election/${id}`); setNoms(data); }
    catch(e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };

  useEffect(()=>{
    (async()=>{
      const list = await getElections();
      if (list?.length){ setElectionId(list[0].election_id); load(list[0].election_id); }
    })();
  },[]);

  const handleChange = async (e)=>{ setElectionId(e.target.value); load(e.target.value); };
  const approve = async (id)=>{ await axios.put(`/nominations/${id}/approve`); load(electionId); };
  const reject = async (id)=>{ const reason = prompt('Reason?') || ''; await axios.put(`/nominations/${id}/reject`, { reason }); load(electionId); };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Nominations</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        <div className="bg-white p-4 rounded shadow mb-4 flex gap-2">
          <label>Election ID</label>
          <input value={electionId} onChange={handleChange} className="border p-2 w-48" />
        </div>
        <div className="bg-white rounded shadow">
          {noms.map(n => (
            <div key={n.nomination_id} className="p-3 border-b flex items-center justify-between">
              <div>
                <div className="font-semibold">{n.student_id}</div>
                <div className="text-sm text-gray-600">{n.status}</div>
              </div>
              <div className="flex gap-2">
                <button onClick={()=>approve(n.nomination_id)} className="text-green-700">Approve</button>
                <button onClick={()=>reject(n.nomination_id)} className="text-red-600">Reject</button>
              </div>
            </div>
          ))}
          {!noms.length && <div className="p-4 text-gray-600">No nominations.</div>}
        </div>
      </div>
    </div>
  );
}
