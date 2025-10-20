import axios from './axiosInstance';

// create election
export const createElection = (data) => axios.post('/elections', data).then(r => r.data);

// get all elections
export const getElections = () => axios.get('/elections').then(r => r.data);

// get one
export const getElection = (id) => axios.get(`/elections/${id}`).then(r => r.data);

// update
export const updateElection = (id, data) => axios.put(`/elections/${id}`, data).then(r => r.data);

// activate election
export const activateElection = (id) => axios.post(`/elections/${id}/activate`).then(r => r.data);

// publish election
export const publishElection = (id) => axios.post(`/elections/${id}/publish`).then(r => r.data);

// bulk publish
export const publishElectionsBulk = (electionIds) => axios.post('/elections/publish/bulk', { election_ids: electionIds }).then(r => r.data);

// notify voting open (announcement)
export const notifyVotingOpen = (id) => axios.post(`/elections/${id}/notify`).then(r => r.data);
export const notifyNominationOpen = (id) => axios.post(`/elections/${id}/notify/nomination-open`).then(r => r.data);

// get my active election (student convenience)
export const getMyActiveElection = () => axios.get('/elections/my/active').then(r => r.data);
export const getMyElections = () => axios.get('/elections/my').then(r => r.data);
