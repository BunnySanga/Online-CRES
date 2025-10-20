import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { listStudents, createStudent, updateStudent, deleteStudent, resetStudentPassword, listClasses } from '../../api/adminApi';
import Select from '../../components/ui/Select';

export default function AdminStudents(){
  const [students, setStudents] = useState([]);
  const [form, setForm] = useState({ student_id:'', name:'', email:'', date_of_birth:'', class_id:'' });
  const [err, setErr] = useState('');
  const [classes, setClasses] = useState([]);
  const [msg, setMsg] = useState('');

  const load = async () => {
    try {
      setErr('');
      const data = await listStudents();
      setStudents(data);
    } catch (e){ setErr(e.response?.data?.error || 'Failed to load'); }
  };
  useEffect(()=>{ load(); (async()=>{ try{ const c = await listClasses(); setClasses(c||[]);}catch{} })(); },[]);

  const submit = async (e) => {
    e.preventDefault(); setErr(''); setMsg('');
    try {
      const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
      if (!gmailRegex.test(String(form.email))) {
        setErr('Only Gmail addresses are supported (example@gmail.com)');
        return;
      }
  const res = await createStudent(form);
  setMsg(`Student created. Default password: ${res?.defaultPassword || '(generated)'}`);
  setForm({ student_id:'', name:'', email:'', date_of_birth:'', class_id:'' });
      load();
    } catch (e){ setErr(e.response?.data?.error || 'Failed to create'); }
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Students</h1>
        {err && <div className="text-red-600 mb-2">{err}</div>}
        {msg && <div className="text-green-600 mb-2">{msg}</div>}

        <form onSubmit={submit} className="bg-white p-4 rounded shadow grid md:grid-cols-2 gap-3 mb-6">
          <label className="text-sm">Student ID <span className="text-red-600">*</span>
            <input placeholder="Student ID" value={form.student_id} onChange={e=>setForm({...form, student_id:e.target.value})} className="border p-2 w-full mt-1" required />
          </label>
          <label className="text-sm">Name <span className="text-red-600">*</span>
            <input placeholder="Name" value={form.name} onChange={e=>setForm({...form, name:e.target.value})} className="border p-2 w-full mt-1" required />
          </label>
          <label className="text-sm">Email <span className="text-red-600">*</span>
            <input placeholder="Email" type="email" value={form.email} onChange={e=>setForm({...form, email:e.target.value})} className="border p-2 w-full mt-1" required />
          </label>
          <label className="text-sm">DOB <span className="text-red-600">*</span>
            <input type="date" placeholder="DOB" value={form.date_of_birth} onChange={e=>setForm({...form, date_of_birth:e.target.value})} className="border p-2 w-full mt-1" required />
          </label>
          <Select label="Class" required value={form.class_id} onChange={e=>setForm({...form, class_id:e.target.value})}>
            <option value="">-- Select Class --</option>
            {classes.map(c => (
              <option key={c.class_id} value={c.class_id}>{c.class_id} - {c.class_name || 'Class'}</option>
            ))}
          </Select>
          <div className="text-xs text-gray-600 md:col-span-2">Default password rule: ddmmyyyynnnn (first 4 of ID). Shown after creation.</div>
          <button disabled={!form.student_id || !form.name || !form.email || !form.date_of_birth || !form.class_id} className="bg-indigo-600 text-white px-4 py-2 rounded disabled:opacity-60">Create</button>
        </form>

        <div className="bg-white rounded shadow overflow-auto">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="bg-gray-100 text-left">
                <th className="p-2">ID</th>
                <th className="p-2">Name</th>
                <th className="p-2">Email</th>
                <th className="p-2">Class</th>
                <th className="p-2">Must Change</th>
                <th className="p-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {students.map(s => (
                <tr key={s.student_id} className="border-b">
                  <td className="p-2">{s.student_id}</td>
                  <td className="p-2">{s.name}</td>
                  <td className="p-2">{s.email}</td>
                  <td className="p-2">{s.class_id}</td>
                  <td className="p-2">{s.must_change_password ? 'Yes' : 'No'}</td>
                  <td className="p-2 flex gap-2">
                    <button onClick={async()=>{ const r = await resetStudentPassword(s.student_id); setMsg(`Temp password for ${s.student_id}: ${r?.tempPassword || '(generated)'} (must change at first login)`); load(); }} className="text-indigo-600">Reset PW</button>
                    <button onClick={async()=>{ await deleteStudent(s.student_id); load(); }} className="text-red-600">Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
