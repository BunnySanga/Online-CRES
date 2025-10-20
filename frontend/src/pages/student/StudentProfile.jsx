import React, { useEffect, useState } from 'react';
import axios from '../../api/axiosInstance';

export default function StudentProfile(){
  const [profile, setProfile] = useState(null);

  useEffect(()=>{
    const fetch = async ()=>{
      try{
        const res = await axios.get('/students/profile');
        setProfile(res.data);
      }catch(err){
        console.error(err);
      }
    }
    fetch();
  },[])

  if(!profile) return <div className="p-6">Loading...</div>

  return (
    <div className="p-6">
      <h1 className="text-2xl font-bold mb-4">Profile</h1>
      <div className="bg-white p-6 rounded shadow max-w-md">
        <div><strong>ID:</strong> {profile.student_id}</div>
        <div><strong>Name:</strong> {profile.name}</div>
        <div><strong>Email:</strong> {profile.email}</div>
        <div><strong>Class:</strong> {profile.class_name}</div>
      </div>
    </div>
  )
}