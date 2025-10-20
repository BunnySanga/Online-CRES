import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Navbar from '../../components/Navbar';
import { getMyActiveElection } from '../../api/electionApi';
import { getMyNotifications } from '../../api/notificationsApi';
import Alert from '../../components/ui/Alert';

export default function StudentDashboard() {
  const [election, setElection] = useState(null);
  const [notices, setNotices] = useState([]);

  useEffect(()=>{
    const fetch = async ()=>{
      try{
        const data = await getMyActiveElection();
        setElection(data || null);
      }catch(err){
        setElection(null);
      }
      try{
        const n = await getMyNotifications();
        setNotices(n||[]);
      }catch{}
    };
    fetch();
  },[]);

  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold mb-4">Student Dashboard</h1>
        <div className="grid md:grid-cols-2 gap-4">
          <div className="bg-white p-4 rounded shadow">
            <h2 className="font-semibold mb-2">Active Election</h2>
            {election ? (
              <>
                <div><strong>ID:</strong> {election.election_id}</div>
                <div><strong>Voting:</strong> {new Date(election.voting_start).toLocaleString()} - {new Date(election.voting_end).toLocaleString()}</div>
                <div className="mt-3 flex gap-2">
                  <Link to="/student/election" className="text-indigo-600">Details</Link>
                  <Link to="/student/nomination" className="text-indigo-600">Nominate</Link>
                  <Link to="/student/vote" className="text-indigo-600">Vote</Link>
                  <Link to="/student/results" className="text-indigo-600">Results</Link>
                </div>
              </>
            ) : (
              <div className="text-gray-600">No active election</div>
            )}
          </div>

          <div className="bg-white p-4 rounded shadow">
            <h2 className="font-semibold mb-2">Notifications</h2>
            {(!notices || notices.length===0) && <div className="text-gray-600">No notifications yet</div>}
            <div className="space-y-2">
              {(notices||[]).map((n, idx) => (
                <Alert key={idx} kind={n.type==='RESULTS_PUBLISHED'?'success': n.type==='VOTING_OPEN'?'info':'warning'}>
                  <div className="text-sm">
                    <span className="font-medium">Election #{n.election_id}:</span> {n.message}
                  </div>
                </Alert>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
