import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getAuditLogs } from '../../api/auditApi';
import Input from '../../components/ui/Input';
import Button from '../../components/ui/Button';

export default function AuditLogs(){
	const [logs, setLogs] = useState([]);
	const [err, setErr] = useState('');
	const [from, setFrom] = useState('');
	const [to, setTo] = useState('');
	const [userId, setUserId] = useState('');
	const [actionType, setActionType] = useState('');
	const [role, setRole] = useState('');

	const load = async () => {
		try{
			const params = {};
			if (from) params.from = from;
			if (to) params.to = to;
			if (userId) params.user_id = userId;
			if (actionType) params.action_type = actionType;
			if (role) params.role = role;
			const data = await getAuditLogs(params);
			setLogs(data || []);
		}catch(e){ setErr(e.response?.data?.error || 'Failed to load'); }
	};

	function extractDisplayValue(l) {
		// prefer explicit meta, then details
		let raw = l.meta ?? l.details ?? '';
		// try to parse if it's a JSON string
		if (typeof raw === 'string') {
			const s = raw.trim();
			if ((s.startsWith('{') || s.startsWith('['))) {
				try { raw = JSON.parse(s); } catch (e) { /* keep as string */ }
			}
		}

		// if it's an object, prefer nested meta or details
		if (raw && typeof raw === 'object') {
			if (raw.meta !== undefined) return raw.meta;
			if (raw.details !== undefined) return raw.details;
		}
		return raw;
	}

	function toDisplayString(val) {
		if (val === null || val === undefined) return '';
		if (typeof val === 'string') return val;
		try { return JSON.stringify(val); } catch (e) { return String(val); }
	}

	function toTitleString(val) {
		if (val === null || val === undefined) return '';
		if (typeof val === 'string') return val;
		try { return JSON.stringify(val, null, 2); } catch (e) { return String(val); }
	}

	useEffect(()=>{ load(); },[]);

	return (
		<div className="min-h-screen bg-gray-50">
			<Navbar />
			<div className="container mx-auto px-6 py-8">
				<h1 className="text-2xl font-bold mb-4">Audit Logs</h1>
				{err && <div className="text-red-600 mb-2">{err}</div>}
						<div className="bg-white p-4 rounded shadow mb-4 grid md:grid-cols-5 gap-3 items-end">
							<Input label="From" type="date" value={from} onChange={e=>setFrom(e.target.value)} />
							<Input label="To" type="date" value={to} onChange={e=>setTo(e.target.value)} />
							<Input label="User ID" value={userId} onChange={e=>setUserId(e.target.value)} />
							<Input label="Action Type" value={actionType} onChange={e=>setActionType(e.target.value)} />
							<Input label="Role" value={role} onChange={e=>setRole(e.target.value)} />
							<div className="md:col-span-5 flex gap-2">
								<Button onClick={load}>Apply Filters</Button>
								<Button variant="secondary" onClick={()=>{ setFrom(''); setTo(''); setUserId(''); setActionType(''); setRole(''); setErr(''); load(); }}>Reset</Button>
							</div>
						</div>

						<div className="bg-white rounded shadow overflow-auto">
					<table className="min-w-full text-sm">
						<thead>
							<tr className="bg-gray-100 text-left">
								<th className="p-2">Timestamp</th>
								<th className="p-2">User</th>
								<th className="p-2">Role</th>
								<th className="p-2">Action</th>
								<th className="p-2">Meta</th>
								<th className="p-2">Outcome</th>
							</tr>
						</thead>
						<tbody>
							{logs.map(l => {
								const displayVal = extractDisplayValue(l);
								const displayStr = toDisplayString(displayVal);
								const titleStr = toTitleString(displayVal);
								return (
									<tr key={l.log_id || `${l.user_id}-${l.timestamp}-${l.action_type}`} className="border-b">
										<td className="p-2 whitespace-nowrap">{new Date(l.timestamp).toLocaleString()}</td>
										<td className="p-2">{l.user_id}</td>
										<td className="p-2">{l.role}</td>
										<td className="p-2">{l.action_type}</td>
										<td className="p-2 max-w-[400px] truncate" title={titleStr}>
											{displayStr}
										</td>
										<td className="p-2" title={l.outcome}>{l.outcome}</td>
									</tr>
								);
							})}
							{!logs.length && (
								<tr><td className="p-4 text-gray-600" colSpan={6}>No logs.</td></tr>
							)}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}
