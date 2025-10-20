import axios from './axiosInstance';

export const getMyProfile = () => axios.get('/students/me').then(r=>r.data);

export const requestPasswordReset = (userId) => axios.post('/auth/request-reset', { userId }).then(r=>r.data);
export const resetPassword = (userId, otp, newPassword) => axios.post('/auth/reset-password', { userId, otp, newPassword }).then(r=>r.data);
