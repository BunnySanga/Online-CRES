import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getMyActiveElection } from '../../api/electionApi';
import { listApprovedByElection } from '../../api/nominationApi';
import { getVoteToken, castVote } from '../../api/voteApi';
import { getPolicy, acceptPolicy } from '../../api/policyApi';

export default function VotePage(){
	const [election, setElection] = useState(null);
	const [candidates, setCandidates] = useState([]);
	const [selected, setSelected] = useState('');
	const [token, setToken] = useState('');
	const [msg, setMsg] = useState('');
	const [err, setErr] = useState('');
	const [loading, setLoading] = useState(false);
	const [policy, setPolicy] = useState(null);
	const [showPolicy, setShowPolicy] = useState(false);
	const [accepted, setAccepted] = useState(false);
  const [alreadyVoted, setAlreadyVoted] = useState(false);

	useEffect(()=>{
		(async () => {
			try {
				const e = await getMyActiveElection();
				setElection(e);
				const list = await listApprovedByElection(e.election_id);
				const normalize = (url) => {
					try {
						if (!url) return url;
						let m = url.match(/drive\.google\.com\/file\/d\/([^/]+)/);
						if (m && m[1]) return `https://drive.google.com/uc?export=view&id=${m[1]}`;
						m = url.match(/[?&]id=([^&]+)/);
						if (m && m[1]) return `https://drive.google.com/uc?export=view&id=${m[1]}`;
						return url;
					} catch { return url; }
				};
				setCandidates((list||[]).map(c => ({ ...c, photo_url: normalize(c.photo_url) })));
          try{ const p = await getPolicy(); setPolicy(p); }catch{}
			} catch (error) {
				setErr(error.response?.data?.error || 'No active election');
			}
		})();
	},[]);

	const getToken = async () => {
		try {
			if (!election) return;
			const res = await getVoteToken(election.election_id);
			setToken(res.token);
			setMsg('Token issued. You can now cast your vote.');
		} catch (e) {
			const apiErr = e.response?.data?.error || 'Failed to get token';
			setErr(apiErr);
			if (apiErr.toLowerCase().includes('already voted')) setAlreadyVoted(true);
		}
	};

	const vote = async () => {
		setErr(''); setMsg(''); setLoading(true);
		try {
			if (!election || !selected || !token) {
				setErr('Please select a candidate and obtain a token.');
				return;
			}
      if (policy && !accepted) { setShowPolicy(true); setLoading(false); return; }
			const res = await castVote({ token, candidate_id: selected, election_id: election.election_id });
			setMsg(res?.message || 'Your vote was recorded');
			setToken('');
			setAlreadyVoted(true);
		} catch (e) {
			const apiErr = e.response?.data?.error || 'Failed to cast vote';
			setErr(apiErr);
			if (apiErr.toLowerCase().includes('already voted')) setAlreadyVoted(true);
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="min-h-screen bg-gray-50">
			<Navbar />
			<div className="container mx-auto px-6 py-8">
				<h1 className="text-2xl font-semibold mb-4">Vote</h1>
				{err && <div className="text-red-600 mb-2">{err}</div>}
				{msg && <div className="text-green-600 mb-2">{msg}</div>}
				{election && (
					<div className="bg-white p-4 rounded shadow mb-4">
						<div className="mb-2"><strong>Election ID:</strong> {election.election_id}</div>
						<button onClick={getToken} disabled={alreadyVoted} className="bg-indigo-600 text-white px-3 py-1 rounded disabled:opacity-60">{alreadyVoted? 'Already Voted' : 'Get Token'}</button>
					</div>
				)}
				<div className="grid md:grid-cols-2 gap-3">
					{candidates.map(c => (
						<label key={c.student_id} className={`bg-white p-4 rounded shadow cursor-pointer border ${selected===c.student_id? 'border-indigo-600' : 'border-transparent'}`}>
							<div className="font-semibold">{c.name} ({c.student_id})</div>
							{c.photo_url && <img src={c.photo_url} alt={c.name} className="w-24 h-24 object-cover rounded mt-2"/>}
							<input type="radio" name="candidate" className="mt-2" checked={selected===c.student_id} onChange={()=>setSelected(c.student_id)} />
						</label>
					))}
				</div>
				<div className="mt-4">
					<button onClick={vote} disabled={alreadyVoted || loading || !selected || !token} className="bg-green-600 text-white px-4 py-2 rounded disabled:opacity-60">{alreadyVoted? 'Vote Submitted' : (loading? 'Submitting...' : 'Submit Vote')}</button>
				</div>

					{showPolicy && policy && (
						<div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4">
							<div className="bg-white rounded shadow max-w-2xl w-full p-4">
								<h2 className="text-lg font-semibold mb-2">Election Policy</h2>
								<div className="h-64 overflow-auto border p-2 whitespace-pre-wrap text-sm mb-3">{policy.policy_text}</div>
								<div className="flex justify-end gap-2">
									<button onClick={()=>setShowPolicy(false)} className="px-3 py-1 rounded border">Cancel</button>
									<button onClick={async ()=>{ try{ await acceptPolicy(); setAccepted(true); setShowPolicy(false); setMsg('Policy accepted. Please submit your vote again.'); }catch(e){ setErr(e.response?.data?.error || 'Failed to accept'); } }} className="px-3 py-1 rounded bg-indigo-600 text-white">I Accept</button>
								</div>
							</div>
						</div>
					)}
			</div>
		</div>
	);
}
