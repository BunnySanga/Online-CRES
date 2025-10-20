import React, { useEffect, useState } from 'react';
import axios from '../../api/axiosInstance';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext';

export default function StudentDashboard() {
  const [election, setElection] = useState(null);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/student/login');
  };

  useEffect(()=>{
    const fetch = async ()=>{
      try{
        const res = await axios.get('/elections/class/1/active'); // backend returns single object or null
        setElection(res.data || null);
      }catch(err){
        console.error(err);
      }
    }
    fetch();
  },[])

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-4">
        <h1 className="text-2xl font-bold">Student Dashboard</h1>
        <button onClick={handleLogout} className="bg-red-600 text-white px-3 py-1 rounded">Logout</button>
      </div>
      <div>
        <p>Welcome to Student area.</p>
      </div>
    </div>
  )
}
