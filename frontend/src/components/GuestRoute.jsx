import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

// GuestRoute: If the user is already authenticated, send them to their role dashboard.
// Otherwise, render the guest-only page (e.g., login, verify OTP, reset password).
export default function GuestRoute({ children }) {
  const { user } = useAuth();

  if (user?.token && user?.role) {
    if (user.role === 'ADMIN') return <Navigate to="/admin/dashboard" replace />;
    return <Navigate to="/student/dashboard" replace />;
  }

  return children;
}
