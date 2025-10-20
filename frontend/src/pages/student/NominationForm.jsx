import React, { useEffect, useState } from 'react';
import Navbar from '../../components/Navbar';
import { getMyElections } from '../../api/electionApi';
import { submitNomination, getMyNomination } from '../../api/nominationApi';
import { getPolicy, acceptPolicy } from '../../api/policyApi';
import Button from '../../components/ui/Button';
import Alert from '../../components/ui/Alert';

export default function NominationForm(){
			const [election, setElection] = useState(null);
			const [allElections, setAllElections] = useState([]);
		const [myNomination, setMyNomination] = useState(null);
	const [manifesto, setManifesto] = useState('');
	const [photoUrl, setPhotoUrl] = useState('');
	const [msg, setMsg] = useState('');
	const [err, setErr] = useState('');
	const [policy, setPolicy] = useState(null);
	const [showPolicy, setShowPolicy] = useState(false);
	const [accepted, setAccepted] = useState(false);

	useEffect(()=>{
		(async () => {
			try {
				const list = await getMyElections();
				setAllElections(list||[]);
				try { const p = await getPolicy(); setPolicy(p); } catch {}
			} catch (error) {
				setErr(error.response?.data?.error || 'Failed to load elections');
			}
		})();
	},[]);

			useEffect(()=>{
			(async ()=>{
				setMyNomination(null);
				if (!election) return;
				try{
					const mine = await getMyNomination(election.election_id);
					setMyNomination(mine);
				}catch{}
			})();
		}, [election]);

		const toDirectImageUrl = (url) => {
			try {
				if (!url) return url;
				// Handle Google Drive share links
				// Formats:
				// - https://drive.google.com/file/d/FILE_ID/view?usp=sharing -> https://drive.google.com/uc?export=view&id=FILE_ID
				// - https://drive.google.com/open?id=FILE_ID -> https://drive.google.com/uc?export=view&id=FILE_ID
				let m = url.match(/drive\.google\.com\/file\/d\/([^/]+)/);
				if (m && m[1]) return `https://drive.google.com/uc?export=view&id=${m[1]}`;
				m = url.match(/[?&]id=([^&]+)/);
				if (m && m[1]) return `https://drive.google.com/uc?export=view&id=${m[1]}`;
				return url;
			} catch { return url; }
		};

		const submit = async (e) => {
		e.preventDefault(); setErr(''); setMsg('');
			try {
				if (!election) throw new Error('Select an election where nominations are open');
				if (myNomination) throw new Error('You have already submitted a nomination for this election');
      if (policy && !accepted) { setShowPolicy(true); return; }
			const normalizedUrl = toDirectImageUrl(photoUrl);
			const res = await submitNomination({ election_id: election.election_id, manifesto, photo_url: normalizedUrl });
			setMsg(res?.message || 'Nomination submitted');
				// mark as submitted locally so the form disables without needing a refetch
				setMyNomination({ submitted: true });
				// optional: clear form fields
				setManifesto('');
				setPhotoUrl('');
		} catch (error) {
			setErr(error.response?.data?.error || error.message || 'Failed to submit');
		}
	};

	return (
		<div className="min-h-screen bg-gray-50">
			<Navbar />
			<div className="container mx-auto px-6 py-8">
						<h1 className="text-2xl font-semibold mb-4">Nomination</h1>
								{err && <Alert kind="danger" className="mb-2">{err}</Alert>}
								{msg && <Alert kind="success" className="mb-2">{msg}</Alert>}

								<div className="bg-white p-4 rounded shadow mb-6">
									<h2 className="font-semibold mb-3">Class Elections</h2>
									<ul className="divide-y">
										{(allElections||[]).map(e => {
											const now = Date.now();
											const ns = new Date(e.nomination_start).getTime();
											const ne = new Date(e.nomination_end).getTime();
											const open = now >= ns && now <= ne;
											return (
												<li key={e.election_id} className="py-3 flex items-center justify-between">
													<div className="text-sm">
														<div className="font-medium">Election #{e.election_id}</div>
														<div className="text-gray-600">Nominations: {new Date(e.nomination_start).toLocaleString()} - {new Date(e.nomination_end).toLocaleString()}</div>
													</div>
													<div>
														<Button variant={open? 'primary':'secondary'} disabled={!open} onClick={()=>setElection(e)}>{open? 'Nominate' : 'Closed'}</Button>
													</div>
												</li>
											);
										})}
										{(!allElections || allElections.length===0) && (
											<li className="py-3 text-gray-600">No elections found for your class.</li>
										)}
									</ul>
								</div>

								{election && (()=>{
									const now = Date.now();
									const ns = new Date(election.nomination_start).getTime();
									const ne = new Date(election.nomination_end).getTime();
									const open = now >= ns && now <= ne;
									if (!open) return null;
									return (
										<form onSubmit={submit} className="bg-white p-4 rounded shadow max-w-xl">
											<h3 className="font-semibold mb-2">Submit Nomination for Election #{election.election_id}</h3>
											{myNomination && (
												<Alert kind="info" className="mb-3">You already submitted a nomination for this election. You can’t submit again.</Alert>
											)}
											<label className="block text-sm mb-2">Manifesto <span className="text-red-600">*</span>
												<textarea value={manifesto} onChange={e=>setManifesto(e.target.value)} placeholder="Your manifesto" className="border p-2 w-full h-32 mt-1 mb-3" required />
											</label>
											<label className="block text-sm mb-2">Photo URL (optional)
												<input value={photoUrl} onChange={e=>setPhotoUrl(e.target.value)} placeholder="https://..." className="border p-2 w-full mt-1 mb-3" />
											</label>
											<Button disabled={!manifesto || !!myNomination} className="px-4">Submit Nomination</Button>
										</form>
									);
								})()}

	        {showPolicy && policy && (
	          <div className="fixed inset-0 bg-black/40 flex items-center justify-center p-4">
	            <div className="bg-white rounded shadow max-w-2xl w-full p-4">
	              <h2 className="text-lg font-semibold mb-2">Election Policy</h2>
	              <div className="h-64 overflow-auto border p-2 whitespace-pre-wrap text-sm mb-3">{policy.policy_text}</div>
								<div className="flex justify-end gap-2">
									<Button variant="secondary" onClick={()=>setShowPolicy(false)}>Cancel</Button>
									<Button onClick={async ()=>{ try{ await acceptPolicy(); setAccepted(true); setShowPolicy(false); setMsg('Policy accepted. Please submit again.'); }catch(e){ setErr(e.response?.data?.error || 'Failed to accept'); } }}>I Accept</Button>
								</div>
	            </div>
	          </div>
	        )}
			</div>
		</div>
	);
}
