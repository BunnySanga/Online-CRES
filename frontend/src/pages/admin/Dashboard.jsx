import React from 'react';
import Navbar from '../../components/Navbar';

export default function Dashboard() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Navbar />
      <div className="container mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold">Admin Dashboard</h1>
        <p className="text-gray-600">Use the navbar to manage students, classes, elections, nominations, and results.</p>
      </div>
    </div>
  );
}
