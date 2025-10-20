import axios from './axiosInstance';

// create election
export const createElection = (data) => axios.post('/elections', data).then(r => r.data);

// get all elections
export const getElections = () => axios.get('/elections').then(r => r.data);

// get one
export const getElection = (id) => axios.get(`/elections/${id}`).then(r => r.data);

// update
export const updateElection = (id, data) => axios.put(`/elections/${id}`, data).then(r => r.data);
