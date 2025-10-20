import React, { useEffect, useState, useMemo } from 'react'; // <-- Import useMemo
import Navbar from '../../components/Navbar';
import { getMyElections } from '../../api/electionApi';
import { getResults } from '../../api/voteApi';
import Select from '../../components/ui/Select';
import Alert from '../../components/ui/Alert';

// 1. Import Chart.js components
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';

// 2. Register the components Chart.js needs
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

export default function ResultsPage() {
    const [electionId, setElectionId] = useState('');
    const [elections, setElections] = useState([]);
    const [results, setResults] = useState([]);
    const [err, setErr] = useState('');
    const [message, setMessage] = useState('');

    useEffect(() => {
        (async () => {
            try {
                const list = await getMyElections();
                setElections(list);
                const published = (list || []).filter(e => e.is_published);
                if (published.length) {
                    setElectionId(String(published[0].election_id));
                }
            } catch (error) {
                setErr(error.response?.data?.error || 'No elections available');
            }
        })();
    }, []);

    useEffect(() => {
        const load = async () => {
            setResults([]); setMessage('');
            if (!electionId) return;
            try {
                const r = await getResults(electionId);
                setResults(r || []);
                if (!r || r.length === 0) {
                    setMessage('No votes recorded. Faculty advisor and HOD will decide next steps.');
                } else {
                    const top = Math.max(...r.map(x => x.votes));
                    const ties = r.filter(x => x.votes === top);
                    if (top === 0) setMessage('No votes recorded. Faculty advisor and HOD will decide next steps.');
                    else if (ties.length > 1) setMessage('Tie detected. Faculty advisor and HOD will resolve.');
                }
            } catch (error) {
                setErr(error.response?.data?.error || 'No results available');
            }
        };
        load();
    }, [electionId]);

    // 3. Prepare data for the bar chart (using useMemo)
    const chartData = useMemo(() => {
        if (!results || results.length === 0) {
            return null;
        }
        return {
            labels: results.map(r => `${r.candidate_name} (${r.candidate_id})`),
            datasets: [
                {
                    label: 'Total Votes',
                    data: results.map(r => r.votes),
                    backgroundColor: 'rgba(79, 70, 229, 0.6)',
                    borderColor: 'rgba(79, 70, 229, 1)',
                    borderWidth: 1,
                },
            ],
        };
    }, [results]);

    // 4. Configure options for the chart
    const chartOptions = {
        responsive: true,
        plugins: {
            legend: {
                display: false,
            },
            title: {
                display: true,
                text: 'Election Results',
                font: {
                    size: 18,
                },
            },
        },
        scales: {
            y: {
                beginAtZero: true,
                ticks: {
                    precision: 0, // No half-votes
                },
            },
            x: {
                beginAtZero: true,
            },
        },
    };

    return (
        <div className="min-h-screen bg-gray-50">
            <Navbar />
            <div className="container mx-auto px-6 py-8">
                <h1 className="text-2xl font-semibold mb-4">Results</h1>
                
                {/* --- Election Selector --- */}
                <div className="mb-4 bg-white p-4 rounded shadow">
                    <Select label="Select Election" value={electionId} onChange={e => setElectionId(e.target.value)}>
                        <option value="">-- Choose --</option>
                        {(elections || []).filter(e => e.is_published).map(e => (
                            <option key={e.election_id} value={e.election_id}>{e.title || `Election #${e.election_id}`} — Voting ended {new Date(e.voting_end).toLocaleString()}</option>
                        ))}
                    </Select>
                </div>

                {/* --- Alerts (for errors, ties, etc.) --- */}
                {err && <Alert kind="danger" className="mb-3">{err}</Alert>}
                {message && <Alert kind="warning" className="mb-3">{message}</Alert>}

                {/* 5. Main Content: Grid or No Results Message */}
                {results.length > 0 ? (
                    // --- Side-by-side Grid Layout ---
                    <div className="grid grid-cols-1 md:grid-cols-5 gap-8">
                        
                        {/* --- Chart Column (Left) --- */}
                        <div className="md:col-span-3">
                            <div className="bg-white rounded shadow p-4">
                                <div style={{ maxHeight: '450px' }}>
                                    <Bar options={chartOptions} data={chartData} />
                                </div>
                            </div>
                        </div>

                        {/* --- Detailed Breakdown Column (Right) --- */}
                        <div className="md:col-span-2">
                            <h2 className="text-xl font-bold mb-3">Detailed Breakdown</h2>
                            <div className="bg-white rounded shadow">
                                {results.map(r => (
                                    <div key={r.candidate_id} className="p-3 border-b flex items-center gap-4">
                                        {r.photo_url && <img src={r.photo_url} alt={r.candidate_name} className="w-10 h-10 rounded object-cover" />}
                                        <div className="flex-1">
                                            <div className="font-semibold">{r.candidate_name} ({r.candidate_id})</div>
                                        </div>
                                        <div className="text-indigo-700 font-bold text-xl">{r.votes}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                ) : (
                    // --- Fallback for No Results ---
                    !err && !message && (
                        <div className="bg-white rounded shadow p-4 text-gray-600">
                            Please select an election to view results.
                        </div>
                    )
                )}
            </div>
        </div>
    );
}