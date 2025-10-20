import axios from './axiosInstance';

export const getMyNotifications = () => axios.get('/notifications/mine').then(r=>r.data);
