import React from 'react';
import { Routes, Route } from 'react-router-dom';
import StudentLogin from './student/StudentLogin';
import StudentDashboard from './student/StudentDashboard';
// import StudentElections from './student/StudentElections'; // Not implemented
// import StudentNominations from './student/StudentNominations'; // Not implemented
// import Vote from './student/Vote'; // Not implemented
import StudentProfile from './student/StudentProfile';
import VerifyOtp from './auth/VerifyOtp';
import ProtectedRoute from '../components/ProtectedRoute';
import { useAuth } from '../context/AuthContext';
import { useEffect } from 'react';

export default function StudentArea(){
  const { user, logout } = useAuth();

  useEffect(() => {
    // If current user is authenticated but not a STUDENT, redirect them to their own dashboard
    if (user?.token && user?.role && user.role !== 'STUDENT') {
      if (user.role === 'ADMIN') window.location.href = '/admin/dashboard';
      else window.location.href = '/';
    }
  }, [user]);

  return (
    <Routes>
      <Route path="login" element={<StudentLogin/>} />
      <Route path="verify-otp" element={<VerifyOtp/>} />
  <Route path="dashboard" element={<ProtectedRoute role="STUDENT"><StudentDashboard/></ProtectedRoute>} />
      {/* <Route path="elections/:id" element={<StudentElections/>} /> */}
      {/* <Route path="elections/:id/vote" element={<Vote/>} /> */}
      {/* <Route path="nominations" element={<StudentNominations/>} /> */}
      {/* <Route path="profile" element={<StudentProfile/>} /> */}
    </Routes>
  )
}