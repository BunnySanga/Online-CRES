import axios from './axiosInstance';

export const getPolicy = () => axios.get('/policy').then(r => r.data);
export const acceptPolicy = () => axios.post('/policy/accept').then(r => r.data);
