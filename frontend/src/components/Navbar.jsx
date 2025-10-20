import React, { useEffect, useState, useRef } from 'react';
import { Link, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

export default function Navbar(){
    const { user, logout } = useAuth();
    const navigate = useNavigate();
    const [open, setOpen] = useState(false); // For mobile menu
    const [isProfileOpen, setIsProfileOpen] = useState(false); // For profile dropdown
    const location = useLocation();
    const profileMenuRef = useRef(null); // Ref for dropdown

    // Close mobile nav when route changes
    useEffect(()=>{ setOpen(false); }, [location.pathname]);

    // Close profile dropdown on click outside
    useEffect(() => {
        function handleClickOutside(event) {
            if (profileMenuRef.current && !profileMenuRef.current.contains(event.target)) {
                setIsProfileOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [profileMenuRef]);

    const handleLogout = () => {
        setIsProfileOpen(false);
        logout();
        if (user?.role === 'ADMIN') navigate('/admin/login');
        else navigate('/student/login');
    };

    const isAdmin = user?.role === 'ADMIN';

    const linkClass = ({isActive}) => `
        block px-4 py-2 rounded-lg transition-all duration-200 no-underline
        ${isActive 
            ? 'bg-indigo-600 text-white font-medium shadow-md shadow-indigo-200/50' 
            : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-100 hover:border-gray-400'
        }
    `;

    const AdminMenu = () => (
        <nav className="flex flex-col md:flex-row md:items-center gap-2 md:gap-3 text-sm">
            <NavLink to="/admin/students" className={linkClass}>Students</NavLink>
            <NavLink to="/admin/classes" className={linkClass}>Classes</NavLink>
            <NavLink to="/admin/elections" className={linkClass}>Elections</NavLink>
            <NavLink to="/admin/nominations" className={linkClass}>Nominations</NavLink>
            <NavLink to="/admin/policy" className={linkClass}>Policy</NavLink>
            <NavLink to="/admin/audit" className={linkClass}>Audit Logs</NavLink>
            <NavLink to="/admin/results" className={linkClass}>Results</NavLink>
        </nav>
    );

    const StudentMenu = () => (
        <nav className="flex flex-col md:flex-row md:items-center gap-2 md:gap-3 text-sm">
            <NavLink to="/student/election" className={linkClass}>Election</NavLink>
            <NavLink to="/student/nomination" className={linkClass}>Nomination</NavLink>
            <NavLink to="/student/vote" className={linkClass}>Vote</NavLink>
            <NavLink to="/student/results" className={linkClass}>Results</NavLink>
        </nav>
    );

    return (
        <header className="bg-white/90 backdrop-blur border-b shadow-sm sticky top-0 z-40">
            <div className="container mx-auto p-4">
                
                {/* --- Top Row (Logo vs Profile/Mobile Button) --- */}
                <div className="flex items-center justify-between">
                    
                    <Link to="/" className="flex items-center gap-3 no-underline">
                        <div className="w-10 h-10 bg-gradient-to-r from-indigo-500 to-blue-500 rounded flex items-center justify-center text-white font-bold">CR</div>
                        <div className="text-lg font-semibold text-gray-800">Class Representative Election System</div>
                    </Link>

                    {user && (
                        <div className="flex items-center">
                            {/* Desktop Profile (Hidden on Mobile) */}
                            <div className="hidden md:block relative" ref={profileMenuRef}>
                                <button
                                    onClick={() => setIsProfileOpen(o => !o)}
                                    className="flex flex-col items-center justify-center w-20 text-center rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                                >
                                    {user?.photo_url ? (
                                        <img src={user.photo_url} alt="Profile" className="w-14 h-14 rounded-full object-cover border border-gray-300" />
                                    ) : isAdmin ? (
                                        <svg className="w-14 h-14 text-indigo-500" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0012 11z" clipRule="evenodd" />
                                        </svg>
                                    ) : (
                                        <svg className="w-14 h-14 text-blue-500" fill="currentColor" viewBox="0 0 20 20" xmlns="http://www.w3.org/2000/svg">
                                            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0012 11z" clipRule="evenodd" />
                                        </svg>
                                    )}
                                    <span 
                                        className={`mt-1 text-xs font-medium uppercase ${isAdmin ? 'text-indigo-600' : 'text-blue-600'}`}
                                    >
                                        {user?.role}
                                    </span>
                                </button>
                                
                                {isProfileOpen && (
                                    <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg z-50 border border-gray-200 overflow-hidden">
                                        <div className="px-4 pt-3 pb-2 border-b border-gray-100">
                                            <span className="block text-xs text-gray-500 uppercase font-medium tracking-wide">{user?.name || user?.role}</span>
                                        </div>
                                        <div className="py-1">
                                            <Link
                                                to={isAdmin ? '/admin/profile' : '/student/profile'}
                                                onClick={() => setIsProfileOpen(false)}
                                                className="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 no-underline"
                                            >
                                                My Profile
                                            </Link>
                                            <div className="border-t border-gray-100"></div>
                                            <button
                                                onClick={handleLogout}
                                                className="block w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-100"
                                            >
                                                Logout
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Mobile Menu Button (Hidden on Desktop) */}
                            <button className="md:hidden inline-flex items-center justify-center p-2 rounded border border-gray-300 text-gray-600" onClick={()=>setOpen(o=>!o)} aria-label="Toggle menu" aria-expanded={open} aria-controls="nav-menu-mobile">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className="w-6 h-6">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" />
                                </svg>
                            </button>
                        </div>
                    )}
                </div>

                {/* --- Bottom Row (Nav Links) --- */}
                {user && (
                    <div>
                        {/* Desktop Nav Links (Hidden on Mobile) - SPACE REDUCED */}
                        <div className="hidden md:block mt-2"> {/* <-- THIS WAS mt-4, NOW IT'S mt-2 */}
                            {isAdmin ? <AdminMenu/> : <StudentMenu/>}
                        </div>

                        {/* Mobile Full Menu (Toggled) */}
                        <div id="nav-menu-mobile" className={`mt-3 md:hidden ${open ? '' : 'hidden'}`}>
                            {isAdmin ? <AdminMenu/> : <StudentMenu/>}
                            
                            <div className="border-t pt-3 mt-3">
                                 <Link
                                    to={isAdmin ? '/admin/profile' : '/student/profile'}
                                    onClick={() => setOpen(false)} 
                                    className="block w-full text-left px-4 py-2 text-sm text-gray-700 hover:bg-gray-100 no-underline rounded-md"
                                >
                                    My Profile
                                </Link>
                                <button
                                    onClick={handleLogout}
                                    className="block w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-gray-100 rounded-md"
                                >
                                    Logout
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </header>
    );
}