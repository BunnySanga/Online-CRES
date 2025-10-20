import axios from './axiosInstance';

export const getAuditLogs = () => axios.get('/audit').then(r => r.data);
