import React, { useEffect, useState, useMemo } from 'react';
import Navbar from '../../components/Navbar';
import { getElections } from '../../api/electionApi'; // Correct: Use getElections
import { getResults } from '../../api/voteApi';
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

export default function AdminResults() {
  const [electionId, setElectionId] = useState('');
  const [results, setResults] = useState([]);
  const [err, setErr] = useState('');
  const [electionsList, setElectionsList] = useState([]);

  const load = async (id) => {
    if (!id) {
      setResults([]);
      return;
    }
    try {
      setErr('');
      const data = await getResults(id);
      setResults(data);
    } catch (e) {
      setResults([]);
      setErr(e.response?.data?.error || 'Failed to load results');
    }
  };

  useEffect(() => {
    (async () => {
      try {
        const list = await getElections();
        setElectionsList(list || []);
      } catch (e) {
        setErr(e.response?.data?.error || 'Failed to load elections list.');
      }
    })();
  }, []);

  // 3. Prepare data for the bar chart
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
          precision: 0,
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
        <h1 className="text-2xl font-bold mb-4">Results</h1>

        {/* --- Election Selector --- */}
        <div className="bg-white p-4 rounded shadow mb-8">
          <label htmlFor="electionSelect" className="block text-sm font-medium text-gray-700 mb-1">
            Select Election
          </label>
          <select
            id="electionSelect"
            value={electionId}
            onChange={e => {
              setElectionId(e.target.value);
              load(e.target.value);
            }}
            className="border p-2 rounded w-full md:w-1/2"
          >
            <option value="">-- Choose --</option>
            {/* --- THIS IS THE LINE THAT WAS CHANGED --- */}
            {electionsList.map(e => (
              <option key={e.election_id} value={e.election_id}>
                {e.title || `Election #${e.election_id}`} 
                {/* Check if voting_end exists before displaying */}
                {e.voting_end ? ` — Voting ended ${new Date(e.voting_end).toLocaleString()}` : ''}
              </option>
            ))}
            {/* --- END OF CHANGE --- */}
          </select>
        </div>

        {/* --- Error Alert --- */}
        {err && <Alert kind="danger" className="mb-6">{err}</Alert>}

        {/* --- Main Content Grid --- */}
        {results.length > 0 ? (
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
          !electionId && !err && (
            <div className="bg-white rounded shadow p-4 text-gray-600">
              Please select an election to view results.
            </div>
          )
        )}
      </div>
    </div>
  );
}