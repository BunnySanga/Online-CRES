import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar(){
	const { user, logout } = useAuth();
	const navigate = useNavigate();

	const handleLogout = () => {
		logout();
		if (user?.role === 'ADMIN') navigate('/admin/login');
		else navigate('/student/login');
	};

	const dashboardPath = user?.role === 'ADMIN' ? '/admin/dashboard' : '/student/dashboard';

		return (
			<header className="bg-white border-b shadow-sm">
				<div className="container mx-auto flex items-center justify-between p-4">
					<div className="flex items-center gap-3">
						  <Link to="/" className="flex items-center gap-3 no-underline">
							<div className="w-10 h-10 bg-gradient-to-r from-indigo-500 to-blue-500 rounded flex items-center justify-center text-white font-bold">CR</div>
							<div className="text-lg font-semibold">Class Representative Election System</div>
						</Link>
					</div>

					<div className="flex items-center gap-4">
						{user ? (
													<div className="flex items-center gap-3">
														  <Link to={dashboardPath} className="text-indigo-600 text-sm no-underline">Dashboard</Link>
														<button onClick={handleLogout} className="bg-red-600 text-white text-sm px-3 py-1 rounded">Logout</button>
													</div>
						) : (
							// keep navbar minimal when no one is signed in; landing has login buttons
							<div />
						)}
					</div>
				</div>
			</header>
		);
}
