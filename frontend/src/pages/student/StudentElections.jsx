import React, { useEffect, useState } from 'react';
import { getMyActiveElection, getMyElections } from '../../api/electionApi';
import Navbar from '../../components/Navbar';
import Badge from '../../components/ui/Badge';

export default function StudentElections(){
	const [activeElection, setActiveElection] = useState(null);
	const [elections, setElections] = useState([]);
	const [err, setErr] = useState('');

	useEffect(()=>{
		const load = async () => {
			try {
				const [active, list] = await Promise.all([
					getMyActiveElection().catch(()=>null),
					getMyElections().catch(()=>[])
				]);
				setActiveElection(active);
				setElections(list || []);
			} catch (e) {
				setErr(e?.response?.data?.error || 'No active election');
			}
		};
		load();
	},[]);

	return (
		<div className="min-h-screen bg-gray-50">
			<Navbar />
			<div className="container mx-auto px-6 py-8">
				<h1 className="text-2xl font-semibold mb-4">My Class Elections</h1>
				{err && <div className="text-red-600">{err}</div>}
				{activeElection && (
					<div className="bg-white p-4 rounded shadow mb-6">
						<h2 className="font-semibold mb-2">Current Election</h2>
						<div className="text-sm text-gray-700"><strong>Nomination:</strong> {new Date(activeElection.nomination_start).toLocaleString()} - {new Date(activeElection.nomination_end).toLocaleString()}</div>
						<div className="text-sm text-gray-700"><strong>Voting:</strong> {new Date(activeElection.voting_start).toLocaleString()} - {new Date(activeElection.voting_end).toLocaleString()}</div>
						<div className="mt-2"><Badge color="emerald">Active</Badge></div>
					</div>
				)}

				<div className="bg-white rounded shadow">
					<div className="p-4 border-b font-semibold">All Elections</div>
					{(elections || []).length === 0 ? (
						<div className="p-4 text-gray-600">No elections found for your class yet.</div>
					) : (
						<ul className="divide-y">
							{elections.map(e => {
								const now = Date.now();
								const ns = new Date(e.nomination_start).getTime();
								const ne = new Date(e.nomination_end).getTime();
								const vs = new Date(e.voting_start).getTime();
								const ve = new Date(e.voting_end).getTime();
								let status = 'Scheduled'; let badge = 'bg-gray-500';
								if (now >= ns && now <= ne) { status = 'Nominations Open'; badge = 'bg-blue-600'; }
								else if (now >= vs && now <= ve) { status = 'Voting Open'; badge = 'bg-emerald-600'; }
								else if (now > ve) { status = e.is_published ? 'Completed' : 'Voting Closed (Pending Results)'; badge = e.is_published ? 'bg-gray-700' : 'bg-orange-600'; }
								return (
									<li key={e.election_id} className="p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between">
										<div className="space-y-1 text-sm">
											<div className="font-medium">Election #{e.election_id}</div>
											<div className="text-gray-600">Nomination: {new Date(e.nomination_start).toLocaleString()} - {new Date(e.nomination_end).toLocaleString()}</div>
											<div className="text-gray-600">Voting: {new Date(e.voting_start).toLocaleString()} - {new Date(e.voting_end).toLocaleString()}</div>
										</div>
										<div className="mt-2 sm:mt-0">
											<Badge color={badge.includes('blue')?'blue': badge.includes('emerald')?'emerald': badge.includes('orange')?'orange':'gray'}>{status}</Badge>
										</div>
									</li>
								);
							})}
						</ul>
					)}
				</div>
			</div>
		</div>
	);
}
