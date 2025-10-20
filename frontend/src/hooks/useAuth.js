import { useContext } from 'react';
import { AuthContext } from '../context/AuthContext';

// simple wrapper to match older imports
export default function useAuth() {
	return useContext(AuthContext);
}
