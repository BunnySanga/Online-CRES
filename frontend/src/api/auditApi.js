import axios from './axiosInstance';

export const getAuditLogs = (params={}) => axios.get('/audit', { params }).then(r => r.data);
