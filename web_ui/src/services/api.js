import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  timeout: 60000,
});

export const getGraph = async () => {
  const { data } = await api.get('/graph');
  return data;
};

export const getBlastRadius = async (nodeId) => {
  const { data } = await api.get(`/blast-radius/${nodeId}`);
  return data;
};

export const getTimeline = async () => {
  const { data } = await api.get('/timeline');
  return data;
};

export const getTimelineSnapshot = async (id) => {
  const { data } = await api.get(`/timeline/${id}`);
  return data;
};

export const getEvents = async () => {
  const { data } = await api.get('/events');
  return data;
};

export default api;
