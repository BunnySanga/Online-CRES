import React from "react";
import { Routes, Route, Link } from "react-router-dom";
import AdminLogin from "./pages/auth/AdminLogin";
import AdminDashboard from "./pages/admin/Dashboard";
import ProtectedRoute from "./components/ProtectedRoute";
import StudentArea from "./pages/StudentArea";
import Navbar from './components/Navbar';

function Landing(){
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  React.useEffect(() => {
    // if token exists, redirect to the matching dashboard automatically
    if (token && role) {
      if (role === 'ADMIN') window.location.href = '/admin/dashboard';
      else window.location.href = '/student/dashboard';
    }
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">
      <Navbar />
      <main className="container mx-auto px-6 py-20">
        <div className="bg-white rounded-lg shadow-lg p-10 flex flex-col items-center gap-8">
          <div className="w-full text-center">
            <h1 className="text-3xl font-bold mb-4 text-indigo-700">Class Representative Election System</h1>
            <p className="text-gray-600 mb-6">Access the administration or student area to manage and participate in class representative elections.</p>
            <div className="flex justify-center gap-4">
              {!token && (
                <>
                  <Link to="/student/login" className="inline-block bg-indigo-600 text-white px-4 py-2 rounded shadow no-underline">Student Login</Link>
                  <Link to="/admin/login" className="inline-block border border-indigo-600 text-indigo-600 px-4 py-2 rounded no-underline">Admin Login</Link>
                </>
              )}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Landing />} />

      <Route path="/admin/login" element={<AdminLogin />} />
      <Route
        path="/admin/dashboard"
        element={
          <ProtectedRoute role="ADMIN">
            <AdminDashboard />
          </ProtectedRoute>
        }
      />

      <Route path="/student/*" element={<StudentArea />} />

      <Route path="*" element={<div className="p-6">Page Not Found</div>} />
    </Routes>
  );
}
