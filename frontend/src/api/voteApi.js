import axios from './axiosInstance';

export const castVote = (payload) => axios.post('/votes', payload).then(r=>r.data);
export const getResults = (electionId) => axios.get(`/votes/election/${electionId}/results`).then(r=>r.data);
export const getVoteToken = (electionId) => axios.get(`/votes/election/${electionId}/token`).then(r=>r.data);
