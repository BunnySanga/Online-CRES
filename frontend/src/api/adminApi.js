import axios from './axiosInstance';

// Classes
export const listClasses = () => axios.get('/admin/classes').then(r=>r.data);
export const createClass = (class_name) => axios.post('/admin/classes', { class_name }).then(r=>r.data);
export const deleteClass = (id) => axios.delete(`/admin/classes/${id}`).then(r=>r.data);

// Students
export const listStudents = () => axios.get('/admin/students').then(r=>r.data);
export const getStudent = (id) => axios.get(`/admin/students/${id}`).then(r=>r.data);
export const createStudent = (payload) => axios.post('/admin/students', payload).then(r=>r.data);
export const updateStudent = (id, payload) => axios.put(`/admin/students/${id}`, payload).then(r=>r.data);
export const deleteStudent = (id) => axios.delete(`/admin/students/${id}`).then(r=>r.data);
export const resetStudentPassword = (id) => axios.post(`/admin/students/${id}/reset-password`).then(r=>r.data);

// Admin profile
export const getAdminProfile = () => axios.get('/admin/profile').then(r=>r.data);
export const updateAdminProfile = (payload) => axios.put('/admin/profile', payload).then(r=>r.data);

// request OTP for admin
export async function requestAdminPasswordReset(adminId) {
  const { data } = await axios.post('/auth/admin/request-reset', { admin_id: adminId });
  return data;
}

// reset password for admin
export async function adminResetPassword(adminId, otp, newPassword) {
  const { data } = await axios.post('/auth/admin/reset-password', {
    admin_id: adminId,
    otp,
    new_password: newPassword,
  });
  return data;
}
