import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getElections, createElection, updateElection, activateElection, publishElection, publishElectionsBulk, notifyVotingOpen, notifyNominationOpen } from '../../api/electionApi';
import Button from '../../components/ui/Button';
import Input from '../../components/ui/Input';
import { useToast } from '../../components/ui/ToastProvider';

export default function AdminElections(){
  const [elections, setElections] = useState([]);
  const [form, setForm] = useState({ class_id:'', nomination_start:'', nomination_end:'', voting_start:'', voting_end:'' });
  const [selected, setSelected] = useState([]);
  const [msg, setMsg] = useState('');
  const { push } = useToast();
  const [err, setErr] = useState('');

  const load = async ()=>{
    try { const list = await getElections(); setElections(list); }
    catch(e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };
  useEffect(()=>{ load(); },[]);

  const submit = async (e)=>{
    e.preventDefault(); setErr(''); setMsg('');
    // client-side strict validation: ns < ne < vs < ve
    try {
      const ns = new Date(form.nomination_start);
      const ne = new Date(form.nomination_end);
      const vs = new Date(form.voting_start);
      const ve = new Date(form.voting_end);
      if (!(ns < ne && ne < vs && vs < ve)) {
        setErr('Invalid timeline: ensure nomination_start < nomination_end < voting_start < voting_end');
        return;
      }
      await createElection(form);
      setMsg('Election created');
      setForm({ class_id:'', nomination_start:'', nomination_end:'', voting_start:'', voting_end:'' });
      load();
    }
    catch(e){ setErr(e.response?.data?.error || 'Failed to create'); }
  };

  const toggleSelect = (id) => {
    setSelected(prev => prev.includes(id) ? prev.filter(x=>x!==id) : [...prev, id]);
  };

  const doBulkPublish = async ()=>{
    try { await publishElectionsBulk(selected); setMsg('Bulk published'); setSelected([]); load(); }
    catch(e){ setErr(e.response?.data?.error || 'Failed bulk publish'); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Elections</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        {msg && <div className="text-green-600 mb-2">{msg}</div>}

        <form onSubmit={submit} className="bg-white p-4 rounded shadow grid md:grid-cols-2 gap-3 mb-6">
          <Input label="Class ID" required placeholder="Class ID" value={form.class_id} onChange={e=>setForm({...form, class_id:e.target.value})} />
          <Input label="Nomination start" required type="datetime-local" value={form.nomination_start} onChange={e=>setForm({...form, nomination_start:e.target.value})} />
          <Input label="Nomination end" required type="datetime-local" value={form.nomination_end} onChange={e=>setForm({...form, nomination_end:e.target.value})} />
          <Input label="Voting start" required type="datetime-local" value={form.voting_start} onChange={e=>setForm({...form, voting_start:e.target.value})} />
          <Input label="Voting end" required type="datetime-local" value={form.voting_end} onChange={e=>setForm({...form, voting_end:e.target.value})} />
          <Button disabled={!form.class_id || !form.nomination_start || !form.nomination_end || !form.voting_start || !form.voting_end}>Create</Button>
        </form>

        <div className="bg-white rounded shadow overflow-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="bg-gray-100 text-left">
                <th className="p-2">Select</th>
                <th className="p-2">ID</th>
                <th className="p-2">Class</th>
                <th className="p-2">Nomination</th>
                <th className="p-2">Voting</th>
                <th className="p-2">Active</th>
                <th className="p-2">Published</th>
                <th className="p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {elections.map(e => (
                <tr key={e.election_id} className="border-b">
                  <td className="p-2"><input type="checkbox" checked={selected.includes(e.election_id)} onChange={()=>toggleSelect(e.election_id)} /></td>
                  <td className="p-2">{e.election_id}</td>
                  <td className="p-2">{e.class_id}</td>
                  <td className="p-2">{new Date(e.nomination_start).toLocaleString()} - {new Date(e.nomination_end).toLocaleString()}</td>
                  <td className="p-2">{new Date(e.voting_start).toLocaleString()} - {new Date(e.voting_end).toLocaleString()}</td>
                  <td className="p-2">{e.is_active ? 'Yes' : 'No'}</td>
                  <td className="p-2">{e.is_published ? 'Yes' : 'No'}</td>
                  <td className="p-2 flex gap-2">
                    {(() => {
                      const now = Date.now();
                      const ve = new Date(e.voting_end).getTime();
                      const canPublish = ve <= now;
                      const disableActivate = e.is_active;
                      return (
                        <>
                          <button onClick={async()=>{ if(disableActivate) return; await activateElection(e.election_id); push('Election activated','success'); load(); }} disabled={disableActivate} className="text-indigo-600 disabled:opacity-50" title={disableActivate? 'Already active' : ''}>Activate</button>
                          <button onClick={async()=>{ await notifyNominationOpen(e.election_id); push('Nomination notifications sent','success'); }} className="text-blue-600">Notify Nomination</button>
                          <button onClick={async()=>{ await notifyVotingOpen(e.election_id); push('Voting notifications sent','success'); }} className="text-blue-600">Notify Voting</button>
                          <button onClick={async()=>{ if(!canPublish) return; await publishElection(e.election_id); push('Results published','success'); load(); }} disabled={!canPublish} className="text-green-700 disabled:opacity-50" title={!canPublish? 'Cannot publish before voting ends' : ''}>Publish</button>
                        </>
                      );
                    })()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="mt-3">
          <button onClick={doBulkPublish} disabled={!selected.length} className="bg-green-600 text-white px-4 py-2 rounded disabled:opacity-50">Publish Selected</button>
        </div>
      </div>
    </div>
  );
}
