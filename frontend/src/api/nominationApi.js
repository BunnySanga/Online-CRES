import axios from './axiosInstance';

// backend expects JSON { election_id, manifesto, photo_url }
export const submitNomination = (payload) => axios.post('/nominations', payload).then(r => r.data);
export const listByElection = (electionId) => axios.get(`/nominations/election/${electionId}`).then(r => r.data);
export const listApprovedByElection = (electionId) => axios.get(`/nominations/election/${electionId}/approved`).then(r => r.data);
export const getMyNomination = (electionId) => axios.get(`/nominations/election/${electionId}/mine`).then(r => r.data);
